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
        Object costFactorObject = initProperties.get(Constants.COST_FACTOR_PROPERTY);
        Object versionObject = initProperties.get(Constants.VERSION_PROPERTY);

        if (costFactorObject != null) {
            try {
                costFactor = Integer.parseInt(costFactorObject.toString());
                validateCostFactor(costFactor);
            } catch (NumberFormatException e) {
                throw new HashProviderClientException(
                        "BCrypt cost factor must be an integer between 4-31. Got: " + costFactorObject, e);
            }
        }

        if (versionObject != null) {
            try {
                version = versionObject.toString();
                validateVersion(version);
            } catch (Exception e) {
                throw new HashProviderClientException(
                        "BCrypt version must be a supported string ('2a', '2y', or '2b'). Got: " + versionObject, e);
            }
        }
    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {
        validatePassword(plainText);

        int byteLength = getUtf8ByteLength(plainText);
        if (byteLength > Constants.BCRYPT_MAX_PLAINTEXT_LENGTH) {
            throw new HashProviderClientException(
                    "Password exceeds BCrypt's 72-byte limit. Length: " + byteLength + " bytes");
        }

        try {
            byte[] saltBytes;

            if (StringUtils.isNotEmpty(salt)) {
                saltBytes = Base64.getDecoder().decode(salt);
                if (saltBytes.length != Constants.BCRYPT_SALT_LENGTH) {
                    throw new HashProviderClientException(
                            "Salt must be exactly 16 bytes when decoded. Got: " + saltBytes.length + " bytes");
                }
            } else {
                String msg = "A salt must be provided for hashing.";
                log.error(msg);
                throw new HashProviderClientException(msg);
            }

            String bcryptHash = OpenBSDBCrypt.generate(version, plainText, saltBytes, costFactor);

            if (log.isDebugEnabled()) {
                log.debug("Generated BCrypt hash: " + bcryptHash);
                log.debug("Hash length: " + bcryptHash.length() + " characters");
            }

            return bcryptHash.getBytes(StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            String msg = "Invalid input for BCrypt hashing.";
            log.error(msg, e);
            throw new HashProviderClientException(msg, e);
        } catch (Exception e) {
            String msg = "Error generating BCrypt hash";
            log.error(msg, e);
            throw new HashProviderServerException(msg, e);
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

    /**
     * Validate cost factor is within acceptable bounds (4-31)
     */
    private void validateCostFactor(int costFactor) throws HashProviderClientException {
        if (costFactor < 4) {
            throw new HashProviderClientException(
                    "BCrypt cost factor too low (minimum: 4). Low values compromise security.");
        }
        if (costFactor > 31) {
            throw new HashProviderClientException(
                    "BCrypt cost factor too high (maximum: 31). High values impact performance.");
        }
    }

    /**
     * Validate BCrypt version is supported
     */
    private void validateVersion(String version) throws HashProviderClientException {
        if (version == null || (!version.equals("2a") && !version.equals("2y") && !version.equals("2b"))) {
            throw new HashProviderClientException(
                    "Unsupported BCrypt version. Must be '2a', '2y', or '2b'. Got: " + version);
        }
    }

    /**
     * Validate password is not null or empty
     */
    private void validatePassword(char[] plainText) throws HashProviderClientException {
        if (plainText == null || plainText.length == 0) {
            throw new HashProviderClientException("Password cannot be null or empty");
        }
    }

    /**
     * Calculate UTF-8 byte length of password
     */
    private int getUtf8ByteLength(char[] chars) {
        if (chars == null || chars.length == 0) {
            return 0;
        }
        return new String(chars).getBytes(StandardCharsets.UTF_8).length;
    }
}