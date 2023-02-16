"""Exceptions for transactions and low level HID errors
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
import ctap.constants
class TransactionStateException(Exception):
    """Exception raised for errors in transaction state.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Incorrect transaction state"):
        self.message = message
        super().__init__(self.message)

class TransactionChannelIDException(Exception):
    """Exception raised when the MSG channel ID does not match the transaction channel ID

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Incorrect channel ID"):
        self.message = message
        super().__init__(self.message)

class ChannelNotFoundException(Exception):
    """Exception raised when a message is received with an unknown channel ID

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Unknown channel ID"):
        self.message = message
        super().__init__(self.message)

class CTAPHIDException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:ctap.constants.CTAPHID_ERROR,message="Something went wrong"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)

    def get_error_code(self)->ctap.constants.CTAPHID_ERROR:
        """Gets the error code in this exception

        Returns:
            ctap.constants.CTAPHID_ERROR: error that is set in the exception
        """
        return self.err_code
