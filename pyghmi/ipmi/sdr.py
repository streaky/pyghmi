# coding=utf8
# Copyright 2014 IBM Corporation
# Copyright 2015 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This module provides access to SDR offered by a BMC

This data is common between 'sensors' and 'inventory' modules since SDR
is both used to enumerate sensors for sensor commands and FRU ids for FRU
commands

For now, we will not offer persistent SDR caching as we do in xCAT's IPMI
code.  Will see if it is adequate to advocate for high object reuse in a
persistent process for the moment.

Focus is at least initially on the aspects that make the most sense for a
remote client to care about.  For example, smbus information is being
skipped for now
"""

import math
import os
import random
import string
import struct
import weakref

import six

import pyghmi.constants as const
import pyghmi.exceptions as exc


TYPE_UNKNOWN = 0
TYPE_SENSOR = 1
TYPE_FRU = 2

shared_sdrs = {}


oem_type_offsets = {
    343: {  # Intel
        149: {  # Cascade Lake-AP
            0x7a: {
                0xda: {
                    3: {
                        'desc': 'Allowed',
                        'severity': const.Health.Ok,
                    },
                    4: {
                        'desc': 'Restricted',
                        'severity': const.Health.Ok,
                    },
                    5: {
                        'desc': 'Disabled',
                        'severity': const.Health.Ok,
                    },
                },
            },
        },
    },
}


def ones_complement(value, bits):
    # utility function to help with the large amount of 2s
    # complement prevalent in ipmi spec
    signbit = 0b1 << (bits - 1)
    if value & signbit:
        # if negative, subtract 1, then take 1s
        # complement given bits width
        return 0 - (value ^ ((0b1 << bits) - 1))
    else:
        return value


def twos_complement(value, bits):
    # utility function to help with the large amount of 2s
    # complement prevalent in ipmi spec
    signbit = 0b1 << (bits - 1)
    if value & signbit:
        # if negative, subtract 1, then take 1s
        # complement given bits width
        return 0 - ((value - 1) ^ ((0b1 << bits) - 1))
    else:
        return value


unit_types = {
    # table 43-15 'sensor unit type codes'
    0: '',
    1: '°C',
    2: '°F',
    3: 'K',
    4: 'V',
    5: 'A',
    6: 'W',
    7: 'J',
    8: 'C',
    9: 'VA',
    10: 'nt',
    11: 'lm',
    12: 'lx',
    13: 'cd',
    14: 'kPa',
    15: 'PSI',
    16: 'N',
    17: 'CFM',
    18: 'RPM',
    19: 'Hz',
    20: 'μs',
    21: 'ms',
    22: 's',
    23: 'min',
    24: 'hr',
    25: 'd',
    26: 'week(s)',
    27: 'mil',
    28: 'inches',
    29: 'ft',
    30: 'cu in',
    31: 'cu feet',
    32: 'mm',
    33: 'cm',
    34: 'm',
    35: 'cu cm',
    36: 'cu m',
    37: 'L',
    38: 'fl. oz.',
    39: 'radians',
    40: 'steradians',
    41: 'revolutions',
    42: 'cycles',
    43: 'g',
    44: 'ounce',
    45: 'lb',
    46: 'ft-lb',
    47: 'oz-in',
    48: 'gauss',
    49: 'gilberts',
    50: 'henry',
    51: 'millihenry',
    52: 'farad',
    53: 'microfarad',
    54: 'ohms',
    55: 'siemens',
    56: 'mole',
    57: 'becquerel',
    58: 'ppm',
    60: 'dB',
    61: 'dBA',
    62: 'dBC',
    63: 'Gy',
    64: 'sievert',
    65: 'color temp deg K',
    66: 'bit',
    67: 'kb',
    68: 'mb',
    69: 'gb',
    70: 'byte',
    71: 'kB',
    72: 'mB',
    73: 'gB',
    74: 'word',
    75: 'dword',
    76: 'qword',
    77: 'line',
    78: 'hit',
    79: 'miss',
    80: 'retry',
    81: 'reset',
    82: 'overrun/overflow',
    83: 'underrun',
    84: 'collision',
    85: 'packets',
    86: 'messages',
    87: 'characters',
    88: 'error',
    89: 'uncorrectable error',
    90: 'correctable error',
    91: 'fatal error',
    92: 'grams',
}

sensor_rates = {
    0: '',
    1: ' per us',
    2: ' per ms',
    3: ' per s',
    4: ' per minute',
    5: ' per hour',
    6: ' per day',
}


class SensorReading(object):
    """Representation of the state of a sensor.

    It is initialized by pyghmi internally, it does not make sense for
    a developer to create one of these objects directly.

    It provides the following properties:
    name: UTF-8 string describing the sensor
    units: UTF-8 string describing the units of the sensor (if numeric)
    value: Value of the sensor if numeric
    imprecision: The amount by which the actual measured value may deviate from
        'value' due to limitations in the resolution of the given sensor.
    """

    def __init__(self, reading, suffix):
        self.broken_sensor_ids = {}
        self.health = const.Health.Ok
        self.type = reading['type']
        self.value = None
        self.imprecision = None
        self.states = []
        self.state_ids = []
        self.unavailable = 0
        try:
            self.health = reading['health']
            self.states = reading['states']
            self.state_ids = reading['state_ids']
            self.value = reading['value']
            self.imprecision = reading['imprecision']
        except KeyError:
            pass
        if 'unavailable' in reading:
            self.unavailable = 1
        self.units = suffix
        self.name = reading['name']

    def __repr__(self):
        return repr({
            'value': self.value,
            'states': self.states,
            'state_ids': self.state_ids,
            'units': self.units,
            'imprecision': self.imprecision,
            'name': self.name,
            'type': self.type,
            'unavailable': self.unavailable,
            'health': self.health
        })

    def simplestring(self):
        """Return a summary string of the reading.

        This is intended as a sampling of how the data could be presented by
        a UI.  It's intended to help a developer understand the relation
        between the attributes of a sensor reading if it is not quite clear
        """
        repr = self.name + ": "
        if self.value is not None:
            repr += str(self.value)
            repr += " ± " + str(self.imprecision)
            repr += self.units
        for state in self.states:
            repr += state + ","
        if self.health >= const.Health.Failed:
            repr += '(Failed)'
        elif self.health >= const.Health.Critical:
            repr += '(Critical)'
        elif self.health >= const.Health.Warning:
            repr += '(Warning)'
        return repr


class SDREntry(object):
    """Represent a single entry in the IPMI SDR.

    This is created and consumed by pyghmi internally, there is no reason for
    external code to pay attention to this class.
    """

    def __init__(self, entrybytes, event_consts, reportunsupported=False,
                 mfg_id=0, prod_id=0):
        self.mfg_id = mfg_id
        self.prod_id = prod_id
        self.event_consts = event_consts
        # ignore record id for now, we only care about the sensor number for
        # moment
        self.readable = True
        self.reportunsupported = reportunsupported
        if entrybytes[2] != 0x51:
            # only recognize '1.5', the only version defined at time of writing
            raise NotImplementedError
        self.rectype = entrybytes[3]
        self.linearization = None
        # most important to get going are 1, 2, and 11
        self.sdrtype = TYPE_SENSOR  # assume a sensor
        if self.rectype == 1:  # full sdr
            self.full_decode(entrybytes[5:])
        elif self.rectype == 2:  # full sdr
            self.compact_decode(entrybytes[5:])
        elif self.rectype == 3:  # event only
            self.eventonly_decode(entrybytes[5:])
        elif self.rectype == 8:  # entity association
            self.association_decode(entrybytes[5:])
        elif self.rectype == 0x11:  # FRU locator
            self.fru_decode(entrybytes[5:])
        elif self.rectype == 0x12:  # Management controller
            self.mclocate_decode(entrybytes[5:])
        elif self.rectype == 0xc0:  # OEM format
            self.sdrtype = TYPE_UNKNOWN   # assume undefined
            self.oem_decode(entrybytes[5:])
        elif self.reportunsupported:
            raise NotImplementedError
        else:
            self.sdrtype = TYPE_UNKNOWN

    @property
    def name(self):
        if self.sdrtype == TYPE_SENSOR:
            return self.sensor_name
        elif self.sdrtype == TYPE_FRU:
            return self.fru_name
        else:
            return "UNKNOWN"

    def oem_decode(self, entry):
        mfgid = entry[0] + (entry[1] << 8) + (entry[2] << 16)
        if self.reportunsupported:
            raise NotImplementedError("No support for mfgid %X" % mfgid)

    def mclocate_decode(self, entry):
        # For now, we don't have use for MC locator records
        # we'll ignore them at the moment
        self.sdrtype = TYPE_UNKNOWN
        pass

    def fru_decode(self, entry):
        # table 43-7 FRU Device Locator
        self.sdrtype = TYPE_FRU
        self.fru_name = self.tlv_decode(entry[10], entry[11:])
        self.fru_number = entry[1]
        self.fru_logical = (entry[2] & 0b10000000) == 0b10000000
        # 0x8  to 0x10..  0 unspecified except on 0x10, 1 is dimm
        self.fru_type_and_modifier = (entry[5] << 8) + entry[6]

    def association_decode(self, entry):
        # table 43-4 Entity Associaition Record
        # TODO(jbjohnso): actually represent this data
        self.sdrtype = TYPE_UNKNOWN

    def eventonly_decode(self, entry):
        # table 43-3 event_only sensor record
        self._common_decode(entry)
        self.sensor_name = self.tlv_decode(entry[11], entry[12:])
        self.readable = False

    def compact_decode(self, entry):
        # table 43-2 compact sensor record
        self._common_decode(entry)
        self.sensor_name = self.tlv_decode(entry[26], entry[27:])

    def assert_trap_value(self, offset):
        trapval = (self.sensor_type_number << 16) + (self.reading_type << 8)
        return trapval + offset

    def _common_decode(self, entry):
        # event only, compact and full are very similar
        # this function handles the common aspects of compact and full
        # offsets from spec, minus 6
        self.has_thresholds = False
        self.sensor_owner = entry[0]
        self.sensor_lun = entry[1] & 0x03
        self.sensor_number = entry[2]
        self.entity = self.event_consts.entity_ids.get(
            entry[3], 'Unknown entity {0}'.format(entry[3]))
        if self.rectype == 3:
            self.sensor_type_number = entry[5]
            self.reading_type = entry[6]  # table 42-1
        else:
            self.sensor_type_number = entry[7]
            self.reading_type = entry[8]  # table 42-1
        if self.rectype == 1 and entry[6] & 0b00001100:
            self.has_thresholds = True
        try:
            self.sensor_type = self.event_consts.sensor_type_codes[
                self.sensor_type_number]
        except KeyError:
            self.sensor_type = "UNKNOWN type " + str(self.sensor_type_number)
        if self.rectype == 3:
            return
        # 0: unspecified
        # 1: generic threshold based
        # 0x6f: discrete sensor-specific from table 42-3, sensor offsets
        # all others per table 42-2, generic discrete
        # numeric format is one of:
        # 0 - unsigned, 1 - 1s complement, 2 - 2s complement, 3 - ignore number
        # compact records are supposed to always write it as '3', presumably
        # to allow for the concept of a compact record with a numeric format
        # even though numerics are not allowed today.  Some implementations
        # violate the spec and do something other than 3 today.  Tolerate
        # the violation under the assumption that things are not so hard up
        # that there will ever be a need for compact sensors supporting numeric
        # values
        if self.rectype == 2:
            self.numeric_format = 3
        else:
            self.numeric_format = (entry[15] & 0b11000000) >> 6
        self.sensor_rate = sensor_rates[(entry[15] & 0b111000) >> 3]
        self.unit_mod = ""
        if (entry[15] & 0b110) == 0b10:  # unit1 by unit2
            self.unit_mod = "/"
        elif (entry[15] & 0b110) == 0b100:
            # combine the units by multiplying, SI nomenclature is either spac
            # or hyphen, so go with space
            self.unit_mod = " "
        self.percent = ''
        if entry[15] & 1 == 1:
            self.percent = '% '
        if self.sensor_type_number == 0xb:
            if self.unit_mod == '':
                if entry[16] == 6:
                    self.sensor_type = 'Power'
            elif self.unit_mod == ' ':
                if entry[16] == 6 and entry[17] in (22, 23, 24):
                    self.sensor_type = 'Energy'
        self.baseunit = unit_types[entry[16]]
        self.modunit = unit_types[entry[17]]
        self.unit_suffix = self.percent + self.baseunit + self.unit_mod + \
            self.modunit

    def full_decode(self, entry):
        # offsets are table from spec, minus 6
        # TODO(jbjohnso): table 43-13, put in constants to interpret entry[3]
        self._common_decode(entry)
        # now must extract the formula data to transform values
        # entry[18 to entry[24].
        # if not linear, must use get sensor reading factors
        # TODO(jbjohnso): the various other values
        self.sensor_name = self.tlv_decode(entry[42], entry[43:])
        self.linearization = entry[18] & 0b1111111
        if self.linearization <= 11:
            # the enumuration of linear sensors goes to 11,
            # static formula parameters are applicable, decode them
            # if 0x70, then the sesor reading will have to get the
            # factors on the fly.
            # the formula could apply if we bother with nominal
            # reading interpretation
            self.decode_formula(entry[19:25])

    def _decode_state(self, state):
        mapping = self.event_consts.generic_type_offsets
        try:
            if self.reading_type in mapping:
                desc = mapping[self.reading_type][state]['desc']
                health = mapping[self.reading_type][state]['severity']
            elif self.reading_type == 0x6f:
                mapping = self.event_consts.sensor_type_offsets
                desc = mapping[self.sensor_type_number][state]['desc']
                health = mapping[self.sensor_type_number][state]['severity']
            elif self.reading_type >= 0x70 and self.reading_type <= 0x7f:
                sensedata = oem_type_offsets[self.mfg_id][self.prod_id][
                    self.reading_type][self.sensor_type_number][state]
                desc = sensedata['desc']
                health = sensedata['severity']
            else:
                desc = "Unknown state %d" % state
                health = const.Health.Ok
        except KeyError:
            desc = "Unknown state %d for reading type %d/sensor type %d" % (
                state, self.reading_type, self.sensor_type_number)
            health = const.Health.Ok
        return desc, health

    def decode_sensor_reading(self, ipmicmd, reading):
        numeric = None
        output = {
            'name': self.sensor_name,
            'type': self.sensor_type,
            'id': self.sensor_number,
        }
        if reading[1] & 0b100000 or not reading[1] & 0b1000000:
            output['unavailable'] = 1
            return SensorReading(output, self.unit_suffix)
        if self.numeric_format == 2:
            numeric = twos_complement(reading[0], 8)
        elif self.numeric_format == 1:
            numeric = ones_complement(reading[0], 8)
        elif self.numeric_format == 0 and (self.has_thresholds or self.reading_type == 1):
            numeric = reading[0]
        discrete = True
        if numeric is not None:
            lowerbound = numeric - (0.5 + (self.tolerance / 2.0))
            upperbound = numeric + (0.5 + (self.tolerance / 2.0))
            lowerbound = self.decode_value(ipmicmd, lowerbound)
            upperbound = self.decode_value(ipmicmd, upperbound)
            output['value'] = (lowerbound + upperbound) / 2.0
            output['imprecision'] = output['value'] - lowerbound
            discrete = False
        upper = 'upper'
        lower = 'lower'
        if self.linearization == 7:
            # if the formula is 1/x, then the intuitive sense of upper and
            # lower are backwards
            upper = 'lower'
            lower = 'upper'
        output['states'] = []
        output['state_ids'] = []
        output['health'] = const.Health.Ok
        if discrete:
            for state in range(8):
                if reading[2] & (0b1 << state):
                    statedesc, health = self._decode_state(state)
                    output['health'] |= health
                    output['states'].append(statedesc)
                    output['state_ids'].append(self.assert_trap_value(state))
            if len(reading) > 3:
                for state in range(7):
                    if reading[3] & (0b1 << state):
                        statedesc, health = self._decode_state(state + 8)
                        output['health'] |= health
                        output['states'].append(statedesc)
                        output['state_ids'].append(
                            self.assert_trap_value(state + 8))
        else:
            if reading[2] & 0b1:
                output['health'] |= const.Health.Warning
                output['states'].append(lower + " non-critical threshold")
                output['state_ids'].append(self.assert_trap_value(1))
            if reading[2] & 0b10:
                output['health'] |= const.Health.Critical
                output['states'].append(lower + " critical threshold")
                output['state_ids'].append(self.assert_trap_value(2))
            if reading[2] & 0b100:
                output['health'] |= const.Health.Failed
                output['states'].append(lower + " non-recoverable threshold")
                output['state_ids'].append(self.assert_trap_value(3))
            if reading[2] & 0b1000:
                output['health'] |= const.Health.Warning
                output['states'].append(upper + " non-critical threshold")
                output['state_ids'].append(self.assert_trap_value(4))
            if reading[2] & 0b10000:
                output['health'] |= const.Health.Critical
                output['states'].append(upper + " critical threshold")
                output['state_ids'].append(self.assert_trap_value(5))
            if reading[2] & 0b100000:
                output['health'] |= const.Health.Failed
                output['states'].append(upper + " non-recoverable threshold")
                output['state_ids'].append(self.assert_trap_value(6))
        return SensorReading(output, self.unit_suffix)

    def _set_tmp_formula(self, ipmicmd, value):
        rsp = ipmicmd.raw_command(netfn=4, command=0x23,
                                  data=(self.sensor_number, value))
        # skip next reading field, not used in on-demand situation
        self.decode_formula(rsp['data'][1:])

    def decode_value(self, ipmicmd, value):
        # Take the input value and return meaningful value
        linearization = self.linearization
        if linearization > 11:  # direct calling code to get factors
            # for now, we will get the factors on demand
            # the facility is engineered such that at construction
            # time the entire BMC table should be fetchable in a reasonable
            # fashion.  However for now opt for retrieving rows as needed
            # rather than tracking all that information for a relatively
            # rare behavior
            self._set_tmp_formula(ipmicmd, value)
            linearization = 0
        # time to compute the pre-linearization value.
        decoded = float((value * self.m + self.b)
                        * (10 ** self.resultexponent))
        if linearization == 0:
            return decoded
        elif linearization == 1:
            return math.log(decoded)
        elif linearization == 2:
            return math.log(decoded, 10)
        elif linearization == 3:
            return math.log(decoded, 2)
        elif linearization == 4:
            return math.exp(decoded)
        elif linearization == 5:
            return 10 ** decoded
        elif linearization == 6:
            return 2 ** decoded
        elif linearization == 7:
            return 1 / decoded
        elif linearization == 8:
            return decoded ** 2
        elif linearization == 9:
            return decoded ** 3
        elif linearization == 10:
            return math.sqrt(decoded)
        elif linearization == 11:
            return decoded ** (1.0 / 3)
        else:
            raise NotImplementedError

    def decode_formula(self, entry):
        self.m = twos_complement(entry[0] + ((entry[1] & 0b11000000) << 2), 10)
        self.tolerance = entry[1] & 0b111111
        self.b = twos_complement(entry[2] + ((entry[3] & 0b11000000) << 2), 10)
        self.accuracy = (entry[3] & 0b111111) + (entry[4] & 0b11110000) << 2
        self.accuracyexp = (entry[4] & 0b1100) >> 2
        self.direction = entry[4] & 0b11
        # 0 = n/a, 1 = input, 2 = output
        self.resultexponent = twos_complement((entry[5] & 0b11110000) >> 4, 4)
        bexponent = twos_complement(entry[5] & 0b1111, 4)
        # might as well do the math to 'b' now rather than wait for later
        self.b = self.b * (10**bexponent)

    def tlv_decode(self, tlv, data):
        # Per IPMI 'type/length byte format
        ipmitype = (tlv & 0b11000000) >> 6
        if not len(data):
            return ""
        if ipmitype == 0:  # Unicode per 43.15 in ipmi 2.0 spec
            # the spec is not specific about encoding, assuming utf8
            return six.text_type(struct.pack("%dB" % len(data), *data),
                                 "utf_8")
        elif ipmitype == 1:  # BCD '+'
            tmpl = "%02X" * len(data)
            tstr = tmpl % tuple(data)
            tstr = tstr.replace("A", " ").replace("B", "-").replace("C", ".")
            return tstr.replace("D", ":").replace("E", ",").replace("F", "_")
        elif ipmitype == 2:  # 6 bit ascii, start at 0x20
            # the ordering is very peculiar and is best understood from
            # IPMI SPEC "6-bit packed ascii example
            tstr = ""
            while len(data) >= 3:  # the packing only works with 3 byte chunks
                tstr += chr((data[0] & 0b111111) + 0x20)
                tstr += chr(((data[1] & 0b1111) << 2) + (data[0] >> 6) + 0x20)
                tstr += chr(((data[2] & 0b11) << 4) + (data[1] >> 4) + 0x20)
                tstr += chr((data[2] >> 2) + 0x20)
            if not isinstance(tstr, str):
                tstr = tstr.decode('utf-8')
            return tstr
        elif ipmitype == 3:  # ACSII+LATIN1
            ret = struct.pack("%dB" % len(data), *data)
            if not isinstance(ret, str):
                ret = ret.decode('utf-8')
            return ret


class SDR(object):
    """Examine the state of sensors managed by a BMC

    Presents the data from sensor read commands as directed by the SDR in a
    reasonable format.  This module is used by the command module, and is not
    intended for consumption by external code directly

    :param ipmicmd: A Command class object
    """
    def __init__(self, ipmicmd, cachedir=None):
        self.ipmicmd = weakref.proxy(ipmicmd)
        self.sensors = {}
        self.fru = {}
        self.cachedir = cachedir
        self.read_info()

    def read_info(self):
        # first, we want to know the device id
        rsp = self.ipmicmd.xraw_command(netfn=6, command=1)
        rsp['data'] = bytearray(rsp['data'])
        self.device_id = rsp['data'][0]
        self.device_rev = rsp['data'][1] & 0b111
        # Going to ignore device available until get sdr command
        # since that provides usefully distinct state and this does not
        self.fw_major = rsp['data'][2] & 0b1111111
        self.fw_minor = "%02X" % rsp['data'][3]  # BCD encoding, oddly enough
        self.ipmiversion = rsp['data'][4]  # 51h = 1.5, 02h = 2.0
        self.mfg_id = (rsp['data'][8] << 16) + (rsp['data'][7] << 8) + \
            rsp['data'][6]
        self.prod_id = (rsp['data'][10] << 8) + rsp['data'][9]
        if len(rsp['data']) > 11:
            self.aux_fw = self.decode_aux(rsp['data'][11:15])
        if rsp['data'][1] & 0b10000000 and rsp['data'][5] & 0b10 == 0:
            # The device has device sdrs, also does not support SDR repository
            # device, so we are meant to use an alternative mechanism to get
            # SDR data
            if rsp['data'][5] & 1:
                # The device has sensor device support, so in theory we should
                # be able to proceed
                # However at the moment, we haven't done so
                raise NotImplementedError
            return
            # We have Device SDR, without SDR Repository device, but
            # also without sensor device support, no idea how to
            # continue
        self.get_sdr()

    def get_sdr_reservation(self):
        rsp = self.ipmicmd.raw_command(netfn=0x0a, command=0x22)
        if rsp['code'] != 0:
            raise exc.IpmiException(rsp['error'])
        return rsp['data'][0] + (rsp['data'][1] << 8)

    def get_sdr(self):
        repinfo = self.ipmicmd.xraw_command(netfn=0x0a, command=0x20)
        repinfo['data'] = bytearray(repinfo['data'])
        if (repinfo['data'][0] != 0x51):
            # we only understand SDR version 51h, the only version defined
            # at time of this writing
            raise NotImplementedError
        # NOTE(jbjohnso): we actually don't need to care about 'numrecords'
        # since FFFF marks the end explicitly
        # numrecords = (rsp['data'][2] << 8) + rsp['data'][1]
        # NOTE(jbjohnso): don't care about 'free space' at the moment
        # NOTE(jbjohnso): most recent timstamp data for add and erase could be
        # handy to detect cache staleness, but for now will assume invariant
        # over life of session
        # NOTE(jbjohnso): not looking to support the various options in op
        # support, ignore those for now, reservation if some BMCs can't read
        # full SDR in one slurp
        modtime = struct.unpack('!Q', bytes(repinfo['data'][5:13]))[0]
        recid = 0
        rsvid = 0  # partial 'get sdr' will require this
        offset = 0
        size = 0xff
        chunksize = 128
        try:
            csdrs = shared_sdrs[
                (self.fw_major, self.fw_minor, self.mfg_id, self.prod_id,
                 self.device_id, modtime)]
            self.sensors = csdrs['sensors']
            self.fru = csdrs['fru']
            return
        except KeyError:
            pass
        cachefilename = None
        self.broken_sensor_ids = {}
        if self.cachedir:
            cachefilename = 'sdrcache-2.{0}.{1}.{2}.{3}.{4}.{5}'.format(
                self.mfg_id, self.prod_id, self.device_id, self.fw_major,
                self.fw_minor, modtime)
            cachefilename = os.path.join(self.cachedir, cachefilename)
        if cachefilename and os.path.isfile(cachefilename):
            with open(cachefilename, 'rb') as cfile:
                csdrlen = cfile.read(2)
                while csdrlen:
                    csdrlen = struct.unpack('!H', csdrlen)[0]
                    self.add_sdr(cfile.read(csdrlen))
                    csdrlen = cfile.read(2)
                for sid in self.broken_sensor_ids:
                    try:
                        del self.sensors[sid]
                    except KeyError:
                        pass
                shared_sdrs[
                    (self.fw_major, self.fw_minor, self.mfg_id, self.prod_id,
                     self.device_id, modtime)] = {
                    'sensors': self.sensors,
                    'fru': self.fru,
                }
                return
        sdrraw = [] if cachefilename else None
        while recid != 0xffff:  # per 33.12 Get SDR command, 0xffff marks end
            newrecid = 0
            currlen = 0
            sdrdata = bytearray()
            while True:  # loop until SDR fetched wholly
                if size != 0xff and rsvid == 0:
                    rsvid = self.get_sdr_reservation()
                rqdata = [rsvid & 0xff, rsvid >> 8,
                          recid & 0xff, recid >> 8,
                          offset, size]
                sdrrec = self.ipmicmd.raw_command(netfn=0x0a, command=0x23,
                                                  data=rqdata)
                if sdrrec['code'] == 0xca:
                    if size == 0xff:  # get just 5 to get header to know length
                        size = 5
                    elif size > 5:
                        size //= 2
                        # push things over such that it's less
                        # likely to be just 1 short of a read
                        # and incur a whole new request
                        size += 2
                        chunksize = size
                    continue
                if sdrrec['code'] == 0xc5:  # need a new reservation id
                    rsvid = 0
                    continue
                if sdrrec['code'] != 0:
                    raise exc.IpmiException(sdrrec['error'])
                if newrecid == 0:
                    newrecid = (sdrrec['data'][1] << 8) + sdrrec['data'][0]
                if currlen == 0:
                    currlen = sdrrec['data'][6] + 5  # compensate for header
                sdrdata.extend(sdrrec['data'][2:])
                # determine next offset to use based on current offset and the
                # size used last time.
                offset += size
                if offset >= currlen:
                    break
                if size == 5 and offset == 5:
                    # bump up size after header retrieval
                    size = chunksize
                if (offset + size) > currlen:
                    size = currlen - offset
            self.add_sdr(sdrdata)
            if sdrraw is not None:
                sdrraw.append(bytes(sdrdata))
            offset = 0
            if size != 0xff:
                size = 5
            if newrecid == recid:
                raise exc.BmcErrorException("Incorrect SDR record id from BMC")
            recid = newrecid
        for sid in self.broken_sensor_ids:
            try:
                del self.sensors[sid]
            except KeyError:
                pass
        shared_sdrs[(self.fw_major, self.fw_minor, self.mfg_id, self.prod_id,
                     self.device_id, modtime)] = {
            'sensors': self.sensors,
            'fru': self.fru,
        }
        if cachefilename:
            suffix = ''.join(
                random.choice(string.ascii_lowercase) for _ in range(12))
            with open(cachefilename + '.' + suffix, 'wb') as cfile:
                for csdr in sdrraw:
                    cfile.write(struct.pack('!H', len(csdr)))
                    cfile.write(csdr)
            os.rename(cachefilename + '.' + suffix, cachefilename)

    def get_sensor_numbers(self):
        for number in self.sensors:
            if self.sensors[number].readable:
                yield number

    def make_sdr_entry(self, sdrbytes):
        return SDREntry(sdrbytes, self.ipmicmd.get_event_constants(),
                        False, self.mfg_id, self.prod_id)

    def add_sdr(self, sdrbytes):
        if not isinstance(sdrbytes[0], int):
            sdrbytes = bytearray(sdrbytes)
        newent = self.make_sdr_entry(sdrbytes)
        if newent.sdrtype == TYPE_SENSOR:
            id = '{0}.{1}.{2}'.format(
                newent.sensor_owner, newent.sensor_number, newent.sensor_lun)
            if id in self.sensors:
                self.broken_sensor_ids[id] = True
                return
            self.sensors[id] = newent
        elif newent.sdrtype == TYPE_FRU:
            id = newent.fru_number
            if id in self.fru:
                self.broken_sensor_ids[id] = True
                return
            self.fru[id] = newent

    def decode_aux(self, auxdata):
        # This is where manufacturers can add their own
        # decode information
        return "".join(hex(x) for x in auxdata)
