#!/usr/bin/python3

import re
import csv

def perf_callback_factory(event_name, data_keys, remap=None):
    """ Return a specialized callback for perf event in bcc.
        TODO: add time offset to d['ts']
    """
    def decorator(func):
        # handle remapped guid key (inverse lookup)
        if remap is not None:
            for oldkey, newkey in remap.items():
                if newkey == 'guid':
                    guid = oldkey
        else:
            guid = 'guid'

        def generic_print(self, cpu, data, size):
            event = self.b[event_name].event(data)
            d = {field:getattr(event, field) for field in data_keys} # a data point in sofa

            d['layer'] = event_name
            d['ts'] = d['ts'] / 1e9
            d[guid] = get_guid_str(d[guid])
            for k, v in d.items():
                try:
                    if type(v) == bytes:
                        d[k] = d[k].decode('utf-8')
                except UnicodeDecodeError as ude:
                    d[k] = ''

            # apply any modification to d
            func(self, d)
            self.log.print(d, remap=remap)
        return generic_print
    return decorator

def get_guid_str(guid_array):
    """ Convert a guid array into string. """
    prefix = guid_array[:12]
    entity = guid_array[12:16]
    prefix_str = '.'.join('{:x}'.format(c) for c in prefix)
    entity_str = '.'.join('{:x}'.format(c) for c in entity)
    return '|'.join([prefix_str, entity_str])

class Log:
    """ sofa_ros2 logging system """
    def __init__(self, fields, fmtstr, cvsfilename=None, print_raw=False):
        self.fields = fields
        self.fmtstr = fmtstr
        if cvsfilename is not None:
            self.f = open(cvsfilename, 'w')
            self.cvslog = csv.DictWriter(self.f, fields)
            self.cvslog.writeheader()

        if print_raw:
            self.print = self.print_raw
        else:
            fieldfmts = re.split(r'\ +', self.fmtstr)
            self.fieldfmts = dict(zip(fields, fieldfmts))
            # extract only width in standard format specifier
            hdrfmt = self.clear_specifiers(fmtstr)
            hdrfmts = re.split(r'\ +', hdrfmt)
            print(' '.join(hdrfmts).format(*fields))

    def close(self):
        if hasattr(self, 'f'):
            self.f.close()

    def clear_specifiers(self, str):
        return re.sub(r'#|[a-zA-Z]|\.\d+', '', str)

    def print(self, data, remap=None):
        """ Write log on console and a csv file. data is of type dictionary """
        fieldfmts = self.fieldfmts.copy()
        # remap keys
        if remap is not None:
            for oldkey, newkey in remap.items():
                data[newkey] = data.pop(oldkey)
        # assign default value to each key
        for field in self.fields:
            if not field in data or data[field] is None:
                data[field] = ''
                fieldfmts[field] = self.clear_specifiers(fieldfmts[field])

        # don't print empty guid
        try:
            if data['guid'] == '0.0.0.0.0.0.0.0.0.0.0.0|0.0.0.0':
                data['guid'] = ''
        except KeyError as e:
            pass

        fmtstr = ' '.join(fieldfmts[field] for field in self.fields)
        interested_data = [data[field] for field in self.fields]
        print(fmtstr.format(*interested_data))

        if hasattr(self, 'f'):
            self.cvslog.writerow(dict(zip(self.fields, interested_data)))

    def print_raw(self, data, remap=None):
        # remap keys
        if remap is not None:
            for oldkey, newkey in remap.items():
                data[newkey] = data.pop(oldkey)
        interested_data = {k:data[k] for k in self.fields if k in data.keys()}

        # don't print empty guid
        try:
            if interested_data['guid'] == '0.0.0.0.0.0.0.0.0.0.0.0|0.0.0.0':
                interested_data['guid'] = ''
        except KeyError as e:
            pass

        print(interested_data)
        if hasattr(self, 'f'):
            self.cvslog.writerow(interested_data)

if __name__ == "__main__":
    log = Log(['ts', 'comm', 'pid', 'topic_name', 'guid', 'seqnum'],
              '{:<14.4f} {:<11} {:<#18x} {:<20} {:<40} {:3d}', 'send_log')

    data = {'func':'rcl_publish', 'ts':324874.41122, 'comm':'talker', 'pid':0x55601bc0f550,
            'topic_name':'/chatter', 'ep_guid':'1.f.e7.13.3.77.0.0.1.0.0.0|0.0.10.3'}
    log.print(data, remap={'ep_guid':'guid'})
    log.close()