/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYSTEM_KEYMASTER_JAVA_CARD_SOFT_KEYMASTER_CONTEXT_H_
#define SYSTEM_KEYMASTER_JAVA_CARD_SOFT_KEYMASTER_CONTEXT_H_

#include <keymaster/contexts/pure_soft_keymaster_context.h>

namespace keymaster {

class SoftKeymasterKeyRegistrations;
class Keymaster0Engine;
class Keymaster1Engine;
class Key;

/**
 * SoftKeymasterContext provides the context for a non-secure implementation of AndroidKeymaster.
 */
class JavaCardSoftKeymasterContext : public keymaster::PureSoftKeymasterContext {
    keymaster_error_t LoadKey(const keymaster_algorithm_t algorithm, KeymasterKeyBlob&& key_material,
                                                AuthorizationSet&& hw_enforced,
                                                AuthorizationSet&& sw_enforced,
                                                UniquePtr<Key>* key) const;
  public:
    // Security level must only be used for testing.
    explicit JavaCardSoftKeymasterContext(
        keymaster_security_level_t security_level = KM_SECURITY_LEVEL_SOFTWARE);
    ~JavaCardSoftKeymasterContext() override;

    keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob,
                                   const AuthorizationSet& additional_params,
                                   UniquePtr<Key>* key) const override;

};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_PURE_SOFT_KEYMASTER_CONTEXT_H_
