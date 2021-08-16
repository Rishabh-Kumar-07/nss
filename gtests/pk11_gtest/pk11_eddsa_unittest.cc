/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"
#include "sechash.h"
#include "cryptohi.h"

#include "cpputil.h"
#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"

#include "pk11_eddsa_vectors.h"
#include "pk11_keygen.h"
#include "pk11_signature_test.h"
namespace nss_test {
static const Pkcs11SignatureTestParams kEddsaVectors[] = {
    {DataBuffer(kEd25519Pkcs8_1, sizeof(kEd25519Pkcs8_1)),
     DataBuffer(kEd25519Spki_1, sizeof(kEd25519Spki_1)),
     DataBuffer(kEd25519Message_1, sizeof(kEd25519Message_1)),
     DataBuffer(kEd25519Signature_1, sizeof(kEd25519Signature_1))},
    {DataBuffer(kEd25519Pkcs8_2, sizeof(kEd25519Pkcs8_2)),
     DataBuffer(kEd25519Spki_2, sizeof(kEd25519Spki_2)),
     DataBuffer(kEd25519Message_2, sizeof(kEd25519Message_2)),
     DataBuffer(kEd25519Signature_2, sizeof(kEd25519Signature_2))},
    {DataBuffer(kEd25519Pkcs8_3, sizeof(kEd25519Pkcs8_3)),
     DataBuffer(kEd25519Spki_3, sizeof(kEd25519Spki_3)),
     DataBuffer(kEd25519Message_3, sizeof(kEd25519Message_3)),
     DataBuffer(kEd25519Signature_3, sizeof(kEd25519Signature_3))},
    {DataBuffer(kEd25519Pkcs8_4, sizeof(kEd25519Pkcs8_4)),
     DataBuffer(kEd25519Spki_4, sizeof(kEd25519Spki_4)),
     DataBuffer(kEd25519Message_4, sizeof(kEd25519Message_4)),
     DataBuffer(kEd25519Signature_4, sizeof(kEd25519Signature_4))}};


class Pkcs11EddsaSha512Test
    : public Pk11SignatureTest,
      public ::testing::WithParamInterface<Pkcs11SignatureTestParams> {
 protected:
  Pkcs11EddsaSha512Test()
      : Pk11SignatureTest(CKM_EDDSA, SEC_OID_UNKNOWN, CKM_EDDSA) {}

};

TEST_P(Pkcs11EddsaSha512Test, SignAndVerify) {
  SignAndVerifyHash(GetParam());
}

TEST_P(Pkcs11EddsaSha512Test, GenerateExportImportSignVerify) {
  GenerateExportImportSignVerify(GetParam());
}

INSTANTIATE_TEST_SUITE_P(EddsaSignVerify, Pkcs11EddsaSha512Test,
                        ::testing::ValuesIn(kEddsaVectors));

}  // namespace