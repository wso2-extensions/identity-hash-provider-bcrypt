/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.hash.provider.bcrypt;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * BCrypt password hashing implementation using OpenBSDBCrypt.
 */
public class BcryptHashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(BcryptHashProvider.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private int costFactor;
    private String version;

    @Override
    public void init() {
        costFactor = Constants.DEFAULT_COST_FACTOR;
        version = Constants.DEFAULT_BCRYPT_VERSION;
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {

        init();
        if (initProperties != null) {
            Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);
            Object versionObject = initProperties.get(Constants.VERSION_PROPERTY);

            if (costFactorObject != null) {
                try {
                    costFactor = Integer.parseInt(costFactorObject.toString());
                    validateCostFactor(costFactor);
                } catch (NumberFormatException e) {
                    throw new HashProviderClientException(
                            ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getDescription(),
                            Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                                    ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getCode());
                }
            }

            if (versionObject != null) {
                version = versionObject.toString();
                validateVersion(version);
            }
        }
    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
        if (plainText == null || plainText.length == 0) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_VALUE.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }

        String actualSalt = salt;
        if (StringUtils.isEmpty(actualSalt)) {
            actualSalt = generateSalt();
        } else {
            validateSalt(actualSalt);
        }

        int byteLength = getUtf8ByteLength(plainText);
        if (byteLength > Constants.BCRYPT_MAX_PLAINTEXT_LENGTH) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_PLAIN_TEXT_TOO_LONG.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_PLAIN_TEXT_TOO_LONG.getCode());
        }

        byte[] saltBytes;
        try {
            saltBytes = Base64.getDecoder().decode(actualSalt);
        } catch (IllegalArgumentException e) {
            log.error(ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getDescription(), e);
            throw new HashProviderServerException(
                    ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getCode(), e);
        }

        if (saltBytes.length != Constants.BCRYPT_SALT_LENGTH) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_SALT_LENGTH.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_SALT_LENGTH.getCode());
        }

        try {
            String bcryptHash = OpenBSDBCrypt.generate(version, plainText, saltBytes, costFactor);
            return bcryptHash.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error(ErrorMessage.ERROR_CODE_HASH_GENERATION_FAILURE.getDescription(), e);
            throw new HashProviderServerException(
                    ErrorMessage.ERROR_CODE_HASH_GENERATION_FAILURE.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_HASH_GENERATION_FAILURE.getCode(), e);
        }
    }

    @Override
    public Map<String, Object> getParameters() {
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        params.put(Constants.VERSION_PROPERTY, version);
        return params;
    }

    @Override
    public String getAlgorithm() {
        return Constants.BCRYPT_HASHING_ALGORITHM;
    }

    @Override
    public boolean supportsValidateHash() {
        return true;
    }

    @Override
    public boolean validateHash(char[] plainText, byte[] hashedPassword, String salt) throws HashProviderException {
        if (plainText == null || hashedPassword == null) {
            return false;
        }

        String storedHash = new String(hashedPassword, StandardCharsets.UTF_8);

        if (plainText.length == 0 || storedHash.length() != 60) {
            return false;
        }

        try {
            return OpenBSDBCrypt.checkPassword(storedHash, plainText);
        } catch (Exception e) {
            log.error(ErrorMessage.ERROR_CODE_VALIDATION_FAILURE.getDescription(), e);
            return false;
        }
    }

    /**
     * Generates a new random salt for hashing.
     *
     * @return The Base64 encoded salt string.
     */
    public String generateSalt() {
        byte[] saltBytes = new byte[Constants.BCRYPT_SALT_LENGTH];
        secureRandom.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /**
     * Validate cost factor is within acceptable bounds (4-31).
     */
    private void validateCostFactor(int costFactor) throws HashProviderClientException {
        if (costFactor < 4 || costFactor > 31) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getCode());
        }
    }

    /**
     * Validate BCrypt version is supported.
     */
    private void validateVersion(String version) throws HashProviderClientException {
        if (version == null || (!version.equals("2a") && !version.equals("2y") && !version.equals("2b"))) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_UNSUPPORTED_BCRYPT_VERSION.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_UNSUPPORTED_BCRYPT_VERSION.getCode());
        }
    }

    /**
     * Validate salt is not null and empty.
     */
    private void validateSalt(String salt) throws HashProviderClientException {
        if (salt == null) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getCode());
        }
    }

    /**
     * Calculate UTF-8 byte length of password.
     */
    int getUtf8ByteLength(char[] chars) {
        if (chars == null || chars.length == 0) {
            return 0;
        }
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}

