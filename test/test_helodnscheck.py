#!/usr/bin/python2.7

import os
import subprocess
import unittest


msg_553 = "R553 sorry, Name or service not known (#5.7.1)\n"
spam_hdr = "HX-Spam-Flag: YES\n"

class TestPlugin(unittest.TestCase):

    def run_plugin(self, domain, ip, whitelist=None):
        os.environ["SMTPHELOHOST"] = domain
        os.environ["TCPREMOTEIP"] = ip
        if whitelist:
            os.environ["HELOWHITELIST"] = whitelist
        output = subprocess.check_output("./testhelo")
        return output

    def test_valid(self):
        self.assertEqual("", self.run_plugin("mail-ea0-f179.google.com", "209.85.215.179"))

    def test_valid_local(self):
        self.assertEqual("", self.run_plugin("localhost", "127.0.0.1"))

    def test_dns_mismatch(self):
        self.assertEqual(spam_hdr, self.run_plugin("localhost", "192.168.20.12"))

    def test_dns_mismatch2(self):
        self.assertEqual(spam_hdr, self.run_plugin("smtp.free.fr", "192.168.0.1"))

    def test_invalid(self):
        self.assertEqual(msg_553, self.run_plugin("does.not.exist", "1.2.3.4"))

    def test_ip_match(self):
        #valid according to the RFC, but only spammers use IP instead
        #of proper DNS name, so reject to further reduce spam
        self.assertEqual(msg_553, self.run_plugin("[1.2.3.4]", "1.2.3.4"))

    def test_ip_mismatch(self):
        self.assertEqual(msg_553, self.run_plugin("[5.6.7.8]", "1.2.3.4"))

    def test_whitelist_match(self):
        self.assertEqual("", self.run_plugin("mx-out.facebook.com", "5.6.7.8", "test/whitelist.txt"))

    def test_whitelist_nomatch(self):
        self.assertEqual(spam_hdr, self.run_plugin("free.fr", "5.6.7.8", "test/whitelist.txt"))


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPlugin)
    unittest.TextTestRunner(verbosity=2).run(suite)

