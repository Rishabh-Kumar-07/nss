/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "cpputil.h"
#include "nss.h"
#include "pk11pub.h"
#include "sechash.h"

#include "nss_scoped_ptrs.h"
#include "databuffer.h"

#include "gtest/gtest.h"

namespace nss_test {

// For test vectors.
struct Pkcs11SignatureTestParams {
  const DataBuffer pkcs8_;
  const DataBuffer spki_;
  const DataBuffer data_;
  const DataBuffer signature_;
};

class Pk11SignatureTest : public ::testing::Test {
 protected:
  Pk11SignatureTest(CK_MECHANISM_TYPE mech, SECOidTag hash_oid,
                    CK_MECHANISM_TYPE combo)
      : mechanism_(mech), hash_oid_(hash_oid), combo_(combo) {
    skip_raw_ = false;
  }

  virtual const SECItem* parameters() const { return nullptr; }
  CK_MECHANISM_TYPE mechanism() const { return mechanism_; }
  void setSkipRaw(bool skip_raw) { skip_raw_ = true; }

  bool ExportPrivateKey(ScopedSECKEYPrivateKey* key, DataBuffer& pkcs8) {
    SECItem* pkcs8Item = PK11_ExportDERPrivateKeyInfo(key->get(), nullptr);
    if (!pkcs8Item) {
      return false;
    }
    pkcs8.Assign(pkcs8Item->data, pkcs8Item->len);
    SECITEM_ZfreeItem(pkcs8Item, PR_TRUE);
    return true;
  }

  ScopedSECKEYPrivateKey ImportPrivateKey(const DataBuffer& pkcs8);
  ScopedSECKEYPublicKey ImportPublicKey(const DataBuffer& spki);

  bool ComputeHash(const DataBuffer& data, DataBuffer* hash) {
    hash->Allocate(static_cast<size_t>(HASH_ResultLenByOidTag(hash_oid_)));
    SECStatus rv =
        PK11_HashBuf(hash_oid_, hash->data(), data.data(), data.len());
    return rv == SECSuccess;
  }

  bool SignHashedData(ScopedSECKEYPrivateKey& privKey, const DataBuffer& hash,
                      DataBuffer* sig);
  bool SignData(ScopedSECKEYPrivateKey& privKey, const DataBuffer& data,
                DataBuffer* sig);
  bool ImportPrivateKeyAndSignHashedData(const DataBuffer& pkcs8,
                                         const DataBuffer& data,
                                         DataBuffer* sig, DataBuffer* sig2);

  /* most primitive verify implemented in pk11_signature_test.cpp */
  void Verify(ScopedSECKEYPublicKey& pubKey, const DataBuffer& data,
              const DataBuffer& sig, bool valid);

  /* quick helper functions that use the primitive verify */
  void Verify(ScopedSECKEYPublicKey& pubKey, const DataBuffer& data,
              const DataBuffer& sig) {
    Verify(pubKey, data, sig, true);
  }

  void Verify(const Pkcs11SignatureTestParams& params, const DataBuffer& sig,
              bool valid) {
    ScopedSECKEYPublicKey pubKey(ImportPublicKey(params.spki_));
    ASSERT_TRUE(pubKey);
    Verify(pubKey, params.data_, sig, valid);
  }

  void Verify(const Pkcs11SignatureTestParams& params, bool valid) {
    Verify(params, params.signature_, valid);
  }

  void Verify(const Pkcs11SignatureTestParams& params) {
    Verify(params, params.signature_, true);
  }

  void SignAndVerify(const Pkcs11SignatureTestParams& params) {
    DataBuffer sig;
    DataBuffer sig2;
    ASSERT_TRUE(ImportPrivateKeyAndSignHashedData(params.pkcs8_, params.data_,
                                                  &sig, &sig2));
    Verify(params, sig, true);
    Verify(params, sig2, true);
  }

  // Importing a private key in PKCS#8 format and reexporting it should
  // result in the same binary representation.
  void ImportExport(const DataBuffer& k) {
    DataBuffer exported;
    ScopedSECKEYPrivateKey key = ImportPrivateKey(k);
    ExportPrivateKey(&key, exported);
    EXPECT_EQ(k, exported);
  }

  void VerifyWithoutHash(const Pkcs11SignatureTestParams& params, const DataBuffer& sig){
    ScopedSECKEYPublicKey pubKey(ImportPublicKey(params.spki_));
    ASSERT_TRUE(pubKey);
    SECItem hashItem;
    DataBuffer hash;
    hashItem = {siBuffer, toUcharPtr(params.data_.data()),
                  static_cast<unsigned int>(params.data_.len())};
    SECItem sigItem = {siBuffer, toUcharPtr(sig.data()),
                       static_cast<unsigned int>(sig.len())};
    SECStatus rv = PK11_VerifyWithMechanism(
        pubKey.get(), mechanism_, parameters(), &sigItem, &hashItem, nullptr);
    EXPECT_EQ(rv, true? SECSuccess : SECFailure);
  }

  bool ImportPrivateKeyAndSignData(const DataBuffer& pkcs8, const DataBuffer& data,
                                    DataBuffer* sig){
      ScopedSECKEYPrivateKey privKey(ImportPrivateKey(pkcs8));
      if (!privKey) {
          printf("Unable to import private key.\n");
          return false;
      }
      return SignHashedData(privKey, data, sig);
  }


  void SignAndVerifyHash(const Pkcs11SignatureTestParams& params){
    DataBuffer sig;
    ASSERT_TRUE(ImportPrivateKeyAndSignData(params.pkcs8_, params.data_,
                                                      &sig));
    VerifyWithoutHash(params, sig);
  }


  void GenerateExportImportSignVerify(const Pkcs11SignatureTestParams& params) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    if (!slot) {
      ADD_FAILURE() << "Couldn't get slot";
      return;
    }

    unsigned char param_buf[65];
    SECItem ecdsa_params = {siBuffer, param_buf, sizeof(param_buf)};
    SECOidData *oid_data = SECOID_FindOIDByTag(SEC_OID_CURVE25519);
    if (!oid_data) {
      ADD_FAILURE() << "Couldn't get oid_data";
      return;
    }
    ecdsa_params.data[0] = SEC_ASN1_OBJECT_ID;
    ecdsa_params.data[1] = oid_data->oid.len;
    memcpy(ecdsa_params.data + 2, oid_data->oid.data, oid_data->oid.len);
    ecdsa_params.len = oid_data->oid.len + 2;

    SECKEYPublicKey *pub_tmp;
    SECKEYPrivateKey *priv_tmp;
    priv_tmp =
        PK11_GenerateKeyPair(slot.get(), CKM_EC_KEY_PAIR_GEN, &ecdsa_params,
                             &pub_tmp, PR_FALSE, PR_FALSE, nullptr);
    if (!pub_tmp || !priv_tmp) {
      ADD_FAILURE() << "PK11_GenerateKeyPair failed";
      return;
    }

    ScopedSECKEYPrivateKey privKey(priv_tmp);

    ScopedSECKEYPublicKey pub(SECKEY_ConvertToPublicKey(priv_tmp));

    //pub.reset(pub_tmp);
    //priv.reset(priv_tmp);

    //DataBuffer exported;
    //ExportPrivateKey(&priv, exported);

    DataBuffer sig;
    DataBuffer data(params.data_.data(), params.data_.len());
    ASSERT_TRUE(SignHashedData(privKey, data, &sig));
    SECItem hashItem;
    DataBuffer hash;

    hashItem = {siBuffer, toUcharPtr(data.data()),
                  static_cast<unsigned int>(data.len())};
    SECItem sigItem = {siBuffer, toUcharPtr(sig.data()),
                       static_cast<unsigned int>(sig.len())};
    //EXPECT_EQ(mechanism_, CKM_NSS_EDDSA_25519_512 ? SECFailure : SECSuccess);

    SECStatus rv = PK11_VerifyWithMechanism(
        pub.get(), mechanism_, parameters(), &sigItem, &hashItem, nullptr);
    EXPECT_EQ(rv, true? SECSuccess : SECFailure);
  }


 private:
  CK_MECHANISM_TYPE mechanism_;
  SECOidTag hash_oid_;
  CK_MECHANISM_TYPE combo_;
  bool skip_raw_;
};

}  // namespace nss_test
