import unittest
import sys
sys.path.append('..')
from lancelot import bucket

SAMPLE_DATA_STRUCTURE = [
    {
        "id": "1",
        "name": "POS1",
        "state": "Online",
    },
    {
        "id": "2",
        "name": "POS2",
        "state": "Online",
    },
    {
        "id": "3",
        "name": "POS1",
        "state": "Online",
    },
    {
        "id": "4",
        "name": "POS3",
        "state": "Online",
    },
    {
        "id": "5",
        "name": "POS3",
        "state": "Online",
    },
    {
        "id": "6",
        "name": "POS3",
        "state": "Online",
    },
    {
        "id": "7",
        "name": "POS4",
        "state": "Online",
    },
    {
        "id": "8",
        "name": "POS5",
        "state": "Online",
    },
    {
        "id": "9",
        "name": "POS6",
        "state": "Online",
    },
]


def f(x): return x['name']


class TestJobSplitting(unittest.TestCase):

    def test_have_all_elements(self):
        c = 0
        buckets = bucket(SAMPLE_DATA_STRUCTURE, f)
        for b in buckets:
            c += len(b)
        self.assertGreater(c, 0)
        self.assertEqual(c, len(SAMPLE_DATA_STRUCTURE))

    def test_no_conflicting_elements(self):
        buckets = bucket(SAMPLE_DATA_STRUCTURE, f)
        for b in buckets:
            ids = [f(x) for x in b]
            self.assertEqual(sorted(ids),
                             sorted(set(ids))
                             )

    def test_havent_discarded_data(self):
        buckets = bucket(SAMPLE_DATA_STRUCTURE, f)
        self.assertEqual(buckets[0][0], SAMPLE_DATA_STRUCTURE[0])
