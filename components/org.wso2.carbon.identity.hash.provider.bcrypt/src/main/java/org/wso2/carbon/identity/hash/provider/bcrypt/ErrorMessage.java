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

/**
 * The ENUM includes all the error messages of hashing.
 */
public enum ErrorMessage {

    // Client Errors.
    ERROR_CODE_INVALID_COST_FACTOR_RANGE("60001", "Invalid cost factor range",
            "Cost factor must be an integer between 4-31."),
    ERROR_CODE_UNSUPPORTED_BCRYPT_VERSION("60002", "Unsupported BCrypt version",
            "Version must be a supported string ('2a', '2y', or '2b')."),
    ERROR_CODE_PLAIN_TEXT_TOO_LONG("60003", "Plain validation failed",
            "Password is too long: Please limit your password to 72 characters."),
    ERROR_CODE_HASH_VALIDATION_FAILED("60004", "Hash validation failed",
            "Failed to validate due to invalid input parameters."),
    ERROR_CODE_SALT_GENERATION_FAILED("60005", "Salt generation failed",
            "Failed to generate secure random salt bytes."),
    ERROR_CODE_HASH_GENERATION_FAILED("60006", "Hash generation failed",
            "Failed to generate BCrypt hash due to invalid input parameters."),
    ERROR_CODE_EMPTY_VALUE("60007", "Empty value", "Value cannot be empty");

    private final String code;
    private final String message;
    private final String description;

    ErrorMessage(String code, String message, String description) {

        this.code = code;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the error code.
     *
     * @return Error code without the scenario prefix.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get error message.
     *
     * @return Error scenario message.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get error scenario description.
     *
     * @return Error scenario description.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return getCode() + " | " + getMessage() + " | " + getDescription();
    }
}
