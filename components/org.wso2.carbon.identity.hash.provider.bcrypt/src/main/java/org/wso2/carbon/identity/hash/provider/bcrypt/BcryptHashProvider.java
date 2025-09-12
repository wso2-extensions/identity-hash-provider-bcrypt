/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.BcryptConstants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * BCrypt password hashing implementation using OpenBSDBCrypt.
 */
public class BcryptHashProvider implements HashProvider {

    private static final Log LOG = LogFactory.getLog(BcryptHashProvider.class);

    private int costFactor;
    private String bcryptVersion;

    @Override
    public void init() {

        costFactor = BcryptConstants.DEFAULT_COST_FACTOR;
        bcryptVersion = BcryptConstants.DEFAULT_BCRYPT_VERSION;
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {

        init();
        if (initProperties != null) {
            Object costFactorObject = initProperties.get(BcryptConstants.COST_FACTOR_PROPERTY);
            Object versionObject = initProperties.get(BcryptConstants.VERSION_PROPERTY);

            if (costFactorObject != null) {
                if (costFactorObject instanceof String) {
                    try {
                        costFactor = Integer.parseInt(costFactorObject.toString());
                    } catch (NumberFormatException e) {
                        throw new HashProviderClientException(
                                ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getDescription(),
                                BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                                        ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getCode(), e);
                    }
                    validateCostFactor(costFactor);
                }
            }
            if (versionObject != null) {
                if (versionObject instanceof String) {
                    bcryptVersion = versionObject.toString();
                    validateBcryptVersion(bcryptVersion);
                }
            }
        }
    }

    /**
     * Calculates the BCrypt hash for the given plain text and salt.
     *
     * @param plainText The plain text to hash.
     * @param salt      The salt to use for hashing.
     * @return The hashed bytes.
     * @throws HashProviderException If hashing fails due to invalid input or other errors.
     */
    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {

        validateEmptyValue(plainText);
        validatePlainTextLength(plainText);
        try {
            String bcryptHash = OpenBSDBCrypt.generate(bcryptVersion, plainText, generateSalt(), costFactor);
            return bcryptHash.getBytes(StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | DataLengthException e) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_HASH_GENERATION_FAILED.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_HASH_GENERATION_FAILED.getCode(), e);
        }
    }

    @Override
    public Map<String, Object> getParameters() {

        Map<String, Object> params = new HashMap<>();
        params.put(BcryptConstants.COST_FACTOR_PROPERTY, costFactor);
        params.put(BcryptConstants.VERSION_PROPERTY, bcryptVersion);
        return params;
    }

    @Override
    public String getAlgorithm() {

        return BcryptConstants.BCRYPT_HASHING_ALGORITHM;
    }

    @Override
    public boolean supportsValidateHash() {

        return true;
    }

    @Override
    public boolean validateHash(char[] plainText, byte[] hashedPassword, String salt) throws HashProviderException {

        String storedHash = new String(hashedPassword, StandardCharsets.UTF_8);
        try {
            return OpenBSDBCrypt.checkPassword(storedHash, plainText);
        } catch (IllegalArgumentException | DataLengthException e) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_HASH_VALIDATION_FAILED.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_HASH_VALIDATION_FAILED.getCode(), e);
        }
    }

    /**
     * Generates a new random salt for hashing.
     *
     * @return The salt bytes.
     * @throws HashProviderException If salt generation fails.
     */
    private byte[] generateSalt() throws HashProviderException {

        try {
            SecureRandom secureRandom = SecureRandom.getInstance(BcryptConstants.RANDOM_ALG_DRBG);
            byte[] saltBytes = new byte[BcryptConstants.BCRYPT_SALT_LENGTH];
            secureRandom.nextBytes(saltBytes);
            return saltBytes;
        } catch (NoSuchAlgorithmException e) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_SALT_GENERATION_FAILED.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_SALT_GENERATION_FAILED.getCode(), e);
        }
    }

    /**
     * Validates plain text length against BCrypt maximum limit.
     *
     * @param plainText The plain text to validate.
     * @throws HashProviderClientException If text exceeds the maximum length limit.
     */
    private void validatePlainTextLength(char[] plainText) throws HashProviderClientException {

        if (getUtf8ByteLength(plainText) > BcryptConstants.BCRYPT_MAX_PLAINTEXT_LENGTH) {
            LOG.warn("Password exceeds maximum allowed length of 72 bytes for bcrypt hashing");
            throw new HashProviderClientException(ErrorMessage.ERROR_CODE_PLAIN_TEXT_TOO_LONG.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_PLAIN_TEXT_TOO_LONG.getCode());
        }
    }

    /**
     * Validate cost factor is within acceptable bounds (4-31).
     *
     * @param costFactor The cost factor to validate.
     * @throws HashProviderClientException If the cost factor is out of valid range.
     */
    private void validateCostFactor(int costFactor) throws HashProviderClientException {

        if (costFactor < BcryptConstants.MIN_COST_FACTOR || costFactor > BcryptConstants.MAX_COST_FACTOR) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_COST_FACTOR_RANGE.getCode());
        }
    }

    /**
     * Validates that the value to be hashed is not empty or null.
     *
     * @param plainText The value which needs to be hashed.
     * @throws HashProviderClientException If the value is null or empty.
     */
    private void validateEmptyValue(char[] plainText) throws HashProviderClientException {

        if (plainText == null || plainText.length == 0) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_VALUE.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * Validate BCrypt version is supported.
     *
     * @param bcryptVersion The version to validate.
     * @throws HashProviderClientException If the version is not supported.
     */
    private void validateBcryptVersion(String bcryptVersion) throws HashProviderClientException {

        if (bcryptVersion == null || !(BcryptConstants.VALID_BCRYPT_VERSIONS).contains(bcryptVersion)) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_UNSUPPORTED_BCRYPT_VERSION.getDescription(),
                    BcryptConstants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_UNSUPPORTED_BCRYPT_VERSION.getCode());
        }
    }

    /**
     * Calculate UTF-8 byte length of password.
     *
     * @param chars The character array to calculate length for.
     * @return The byte length when encoded in UTF-8.
     */
    int getUtf8ByteLength(char[] chars) {

        if (chars == null || chars.length == 0) {
            return 0;
        }
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}
