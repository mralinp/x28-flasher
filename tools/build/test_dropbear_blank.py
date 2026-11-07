import unittest

import first_boot as f

INIT = '\tprocd_set_param command "$PROG" -F -P "$pid_file"\n'


class AllowBlankPasswordTests(unittest.TestCase):
    def test_adds_dash_b_once(self):
        self.assertEqual(f.allow_blank_password(INIT), '\tprocd_set_param command "$PROG" -B -F -P "$pid_file"\n')

    def test_refuses_an_init_script_it_does_not_recognise(self):
        for init in ("", INIT + INIT, "other\n"):
            with self.assertRaises(ValueError):
                f.allow_blank_password(init)


if __name__ == "__main__":
    unittest.main()
