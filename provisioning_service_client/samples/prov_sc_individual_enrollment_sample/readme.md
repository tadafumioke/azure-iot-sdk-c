# Provisioning Service Client Sample for Individual Enrollment

## Overview

This is a quick tutorial with the steps to create, update, get, and delete an Individual Enrollment on the Microsoft Azure IoT Hub Device Provisioning Service using the C SDK.

## References

[Source Code][source-code-link]

## How to run the sample on Linux or Windows

1. Clone the [C SDK repository](https://github.com/Azure/azure-iot-sdk-c)
2. Compile the C SDK as shown [here][devbox-setup-link], using the `-Duse_prov_client=ON` flag.
3. Edit `provisioning_individual_enrollment_sample.c` to add your provisioning service information:
    1. Replace the `[Connection String]` with the Provisioning Connection String copied from your Device Provisiong Service on the Portal.
        ```c
        const char* connectionString = "[Connection String]";
        ```

    2. For a **TPM Attestation** (as shown in the sample):
        1. From the device that you have, you must copy the Registration ID and Endorsement Key. If you do not have a physical device with a TPM, you can use the [TPM Simulator][tpm-simulator-link]
        2. Replace the `[Registration Id]` with the Reigstration ID, and `[Endorsement Key]` with the Endorsement Key.
            ```c
            const char* registrationId = "[Registration Id]";
            const char* endorsementKey = "[Endorsement Key]";
            ```
        3. Optionally, Replace the `[Device Id]` with a Device ID.
            ```c
            const char* deviceId = "[Device Id]";
            ```
    3. For a **X509 Attestation** (not shown in this sample):
        1. From the device that you have, you must copy the Registration ID and the Client Certificate. You can use a physical device with [DICE][dice-link], or use a certificate you generate yourself. One possible way to do this is to use the included [CA Certificates Tool][ca-cert-link].
        2. Replace the `[Registration Id]` with the Registration ID, and define a variable `clientCertificate` containing your Client Certificate
            ```c
            const char* registrationId = "[Registration Id]";
            const char* clientCertificate = "[Client Certificate]";
            ```
            Note that a certificate format can be just the Base 64 encoding, or can include the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` tags, either works.

        3. Replace the TPM Attestation Mechanism in the sample with an X509 Attestation Mechanism.

            **Replace**
            ```c
            if ((am_handle = attestationMechanism_createWithTpm(endorsementKey)) == NULL)
            {
                printf("Failed calling attestationMechanism_createWithTpm\n");
                result = __FAILURE__;
            }
            ```
            **With**
            ```c
            if ((am_handle = attestationMechanism_createWithX509ClientCert(clientCertificate, NULL)) == NULL)
            {
                printf("Failed calling attestationMechanism_createWithX509ClientCert\n");
                result = __FAILURE__;
            }
            ```
4. Build as shown [here][devbox-setup-link] and run the sample.

[source-code-link]: ../../src
[tpm-simulator-link]: https://github.com/Azure/azure-iot-sdk-java/tree/master/provisioning/provisioning-tools/tpm-simulator
[dice-link]: https://azure.microsoft.com/en-us/blog/azure-iot-supports-new-security-hardware-to-strengthen-iot-security/
[devbox-setup-link]: ../../../doc/devbox-setup.md
[ca-cert-link]: ../../../tools/CACertificates