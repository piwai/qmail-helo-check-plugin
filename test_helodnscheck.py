#!/usr/bin/python2.7

import os
import subprocess
import unittest


class TestPlugin(unittest.TestCase):


    def run_plugin(self, domain, ip):
        os.environ["SMTPHELOHOST"] = domain
        os.environ["TCPREMOTEIP"] = ip
        output = subprocess.check_output("./testhelo")
        return output




    def test_invalid(self):
        self.assertEqual("R553 sorry, Name or service not known (#5.7.1)\n",
                         self.run_plugin("does.not.exist", "1.2.3.4"))

    def test_valid(self):
        self.assertEqual("", self.run_plugin("mail-ea0-f179.google.com", "209.85.215.179"))

    def test_dns_mismatch(self):
        self.assertEqual("HX-Spam-Flag: YES\n", self.run_plugin("localhost", "192.168.20.12"))


if __name__ == "__main__":
    unittest.main()
