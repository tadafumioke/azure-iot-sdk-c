# Provisioning Service Client Sample for Enrollment Group

## Overview

This is a quick tutorial with the steps to create, update, get, and delete an Enrollment Group on the Microsoft Azure IoT Hub Device Provisioning Service using the C SDK.

## References

[Source Code][source-code-link]

## How to run the sample on Linux or Windows

1. Clone the [C SDK repository][root-link]
2. Compile the C SDK as shown [here][devbox-setup-link], using the `-Duse_prov_client=ON` flag.
3. Edit `provisioning_enrollment_group_sample.c` to add your provisioning service information:
    1. Replace the `[Connection String]` with the Provisioning Connection String copied from your Device Provisiong Service on the Portal.
        ```c
        const char* connectionString = "[Connection String]";
        ```
    2. From the device that you have, you must copy the Group ID and the Client Certificate. You can use a physical device with [DICE][dice-link], or use a certificate you generate yourself. One possible way to do this is to use the included [CA Certificates Tool][ca-cert-link].
    2. Replace the `[groupId]` with the Group ID, and define a variable `clientCertificate` containing your Client Certificate
        ```c
        const char* groupId = "[Group Id]";
        const char* clientCertificate = "[Client Certificate]";
        ```
        Note that a certificate format can be just the Base 64 encoding, or can include the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` tags, either works.

4. Build as shown [here][devbox-setup-link] and run the sample.

[root-link]: ../../..
[source-code-link]: ../../src
[dice-link]: https://azure.microsoft.com/en-us/blog/azure-iot-supports-new-security-hardware-to-strengthen-iot-security/
[devbox-setup-link]: ../../../doc/devbox-setup.md
[ca-cert-link]: ../../../tools/CACertificates