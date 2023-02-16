"""Contains classes for the various different parameters and
datatypes that are used by messages and CTAP, as well as the
exception class used by authenticators
Classes:

 * :class:`AuthenticatorVersion`
 * :class:`BridgeException`
"""
"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
from enum import Enum
import ctap.constants

class AuthenticatorVersion:
    """Utility class to hold the Authenticator Version
    """
    def __init__(self, ctaphid_protocol_version:int=2,
        major_version:int=1, minor_version:int=0, build_version:int=0):
        self.ctaphid_protocol_version=ctaphid_protocol_version
        self.major_version=major_version
        self.minor_version=minor_version
        self.build_version=build_version

class BridgeException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:ctap.constants.CTAP_STATUS_CODE,message="Authenticator Exception"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)

    def get_error_code(self)->ctap.constants.CTAP_STATUS_CODE:
        """Get the error code that has been set in this exception

        Returns:
            ctap.constants.CTAP_STATUS_CODE: error code
        """
        return self.err_code
