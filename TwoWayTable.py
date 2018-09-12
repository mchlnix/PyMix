# pylint: disable=E1101

class TwoWayTable():
    def __init__(self, key_name, value_name, *, 
                 keylist_name=None, valuelist_name=None):
        if keylist_name is None:
            keylist_name = key_name + "s"

        if valuelist_name is None:
            valuelist_name = value_name + "s"

        self.dict1 = {}
        self.dict2 = {}
        setattr(self, key_name, PairedDict(self.dict1, self.dict2))
        setattr(self, value_name, PairedDict(self.dict2, self.dict1))
        setattr(self, keylist_name, self.values)
        setattr(self, valuelist_name, self.keys)

    @property
    def keys(self):
        return self.dict1.keys()

    @property
    def values(self):
        return self.dict1.values()

class PairedDict():
    def __init__(self, wrapped_dict, partner_dict):
        self.internal = wrapped_dict
        self.partner = partner_dict

    def __setitem__(self, key, item):
        self.internal[key] = item

        # check to avoid infinite recursion
        if item not in self.partner:
            self.partner[item] = key

    def __getitem__(self, key):
        return self.internal[key]

    def __delitem__(self, key):
        item = self.internal[key]

        del self.internal[key]

        # check to avoid infinite recursion
        if item in self.partner:
            del self.partner[item]

    def __len__(self):
        return len(self.internal)

    def __iter__(self):
        return iter(self.internal)

    def clear(self):
        self.internal.clear()

        # check to avoid infinite recursion
        if len(self.partner):
            self.partner.clear()
