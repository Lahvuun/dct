import unittest

from dct import dct as dictionary


class TestJenkins(unittest.TestCase):
    def test_ss_console_dlc_strings(self):
        test_data = (
            (0xbfb9cdd0, 'TEXT_CARDESCR_Musclecar_Ghost'),
            (0xaa47aea0, 'TEXT_CARDESCR_Musclecar_Drone'),
            (0xb413ae8b, 'TEXT_CARDESCR_Placeholder_11'),
            (0x7d9dbbde, 'TEXT_PLACEHOLDER_11'),
            (0x45ea8f64, 'TEXT_CARDESCR_Placeholder_10'),
            (0xf9f3b7aa, 'TEXT_PLACEHOLDER_10'),
            (0xa14b3743, 'TEXT_CARDESCR_Placeholder_09'),
            (0x6c67b5e0, 'TEXT_PLACEHOLDER_09'),
            (0x1a7a9469, 'TEXT_CARDESCR_Placeholder_08'),
            (0x7271a852, 'TEXT_PLACEHOLDER_08'),
            (0x6f204575, 'TEXT_CARDESCR_Placeholder_07'),
            (0xa21926e8, 'TEXT_PLACEHOLDER_07'),
            (0x35cc692f, 'TEXT_CARDESCR_Placeholder_06'),
            (0x8c4cb3c6, 'TEXT_PLACEHOLDER_06'),
            (0x214dd6e2, 'TEXT_CARDESCR_Placeholder_05'),
            (0x977bbd38, 'TEXT_PLACEHOLDER_05'),
            (0xe5e3f2b8, 'TEXT_CARDESCR_Placeholder_04'),
            (0x73081644, 'TEXT_PLACEHOLDER_04'),
            (0x999a46f1, 'TEXT_CARDESCR_Placeholder_03'),
            (0x42c29af9, 'TEXT_PLACEHOLDER_03'),
            (0x1946c814, 'TEXT_CARDESCR_Placeholder_02'),
            (0x61025a6b, 'TEXT_PLACEHOLDER_02'),
            (0x58f59082, 'TEXT_CARDESCR_Placeholder_01'),
            (0x0fc60abc, 'TEXT_PLACEHOLDER_01'),
            (0x9293adf3, 'TEXT_Quarry_A_SUBTRACK'),
            (0x513ba8ee, 'TEXT_Quarry_A_TRACK'),
            (0x5632106e, 'TEXT_quarry_A'),
            (0x7af0e34d, 'TEXT_nem_quarry_A_SUBTRACK'),
            (0xf5977b1b, 'TEXT_nem_quarry_A_TRACK'),
            (0xf2fbdaa2, 'TEXT_nem_quarry_A'),
        )

        for h, s in test_data:
            self.assertEqual(dictionary.hash_jenkins(s.lower().encode("utf-8"), len(s), 0xf5e9b889), h)
