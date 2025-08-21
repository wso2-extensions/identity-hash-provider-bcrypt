
/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Test class for BcryptHashProvider.
 */
public class BcryptHashProviderTest {

    private static BcryptHashProvider bcryptHashProvider = null;
    private static final SecureRandom random = new SecureRandom();

    @BeforeClass
    public void initialize() {

        bcryptHashProvider = new BcryptHashProvider();
    }

    @Test
    public void testInitWithDefaultCostFactor() {

        bcryptHashProvider.init();
        Map<String, Object> params = bcryptHashProvider.getParameters();
        Assert.assertEquals(params.get(Constants.COST_FACTOR_PROPERTY),
                Constants.DEFAULT_COST_FACTOR);
    }

    @DataProvider(name = "initConfigParams")
    public Object[][] initConfigParams() {
        return new Object[][]{
                {"10"},
                {"12"},
                {"14"}
        };
    }

    @Test(dataProvider = "initConfigParams")
    public void testInitWithCustomCostFactor(String costFactor) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        bcryptHashProvider.init(initProperties);
        Map<String, Object> params = bcryptHashProvider.getParameters();
        Assert.assertEquals(params.get(Constants.COST_FACTOR_PROPERTY),
                Integer.parseInt(costFactor));
    }

    @Test(expectedExceptions = HashProviderClientException.class,
            expectedExceptionsMessageRegExp = "Invalid value for the Bcrypt cost factor. It must be an integer.")
    public void testInitWithInvalidCostFactorType() throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, "invalid_string");
        bcryptHashProvider.init(initProperties);
    }

    @Test(expectedExceptions = HashProviderClientException.class,
            expectedExceptionsMessageRegExp = "Bcrypt cost factor must be a positive integer.")
    public void testInitWithZeroCostFactor() throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, "0");
        bcryptHashProvider.init(initProperties);
    }

    @DataProvider(name = "getHash")
    public Object[][] getHash() {
        byte[] salt1 = new byte[16];
        random.nextBytes(salt1);
        String base64Salt1 = Base64.getEncoder().encodeToString(salt1);

        byte[] salt2 = new byte[16];
        random.nextBytes(salt2);
        String base64Salt2 = Base64.getEncoder().encodeToString(salt2);

        return new Object[][]{
                {"test1234".toCharArray(), base64Salt1, 12},
                {"password".toCharArray(), base64Salt2, 10}
        };
    }

    @Test(dataProvider = "getHash")
    public void testCalculateHash(char[] plainText, String salt, int costFactor)
            throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, String.valueOf(costFactor));
        bcryptHashProvider.init(initProperties);

        byte[] calculatedHashBytes = bcryptHashProvider.calculateHash(plainText, salt);
        String calculatedHash = new String(calculatedHashBytes, StandardCharsets.UTF_8);

        boolean isVerified = OpenBSDBCrypt.checkPassword(calculatedHash, plainText);
        Assert.assertTrue(isVerified,
                "The calculated hash should be valid for the given password.");
    }

    @DataProvider(name = "hashProviderErrorScenarios")
    public Object[][] hashProviderErrorScenarios() {
        return new Object[][]{
                // Password length greater than 72 characters.
                {"thispasswordiswaytoolongtobeusedinabacryptanditshouldbevalidatedandthrownanerror".toCharArray(),
                        "a16bytelongsalt1", "Password length exceeds the maximum allowed by Bcrypt (72 characters)."},
                // Invalid Base64 salt.
                {"test1234".toCharArray(), "short", "Invalid Base64 salt provided."},
                // Incorrect salt length (16 bytes required).
                {"test1234".toCharArray(), Base64.getEncoder().encodeToString
                        ("15bytelongsalt_".getBytes(StandardCharsets.UTF_8)),
                        "Salt length is not 16 bytes, but is 15."},
        };
    }

    @Test(dataProvider = "hashProviderErrorScenarios")
    public void testHashProviderErrorScenarios(char[] plainText, String salt, String expectedMessage) {
        try {
            if (expectedMessage.contains("cost factor")) {
                Map<String, Object> initProperties = new HashMap<>();
                initProperties.put(Constants.COST_FACTOR_PROPERTY, "0");
                bcryptHashProvider.init(initProperties);
            } else {
                bcryptHashProvider.init();
            }
            bcryptHashProvider.calculateHash(plainText, salt);
            Assert.fail("Expected a HashProviderException but no exception was thrown.");
        } catch (HashProviderException e) {
            Assert.assertEquals(e.getMessage(), expectedMessage,
                    "Unexpected error message.");
        }
    }

    @Test
    public void testGetAlgorithm() {
        Assert.assertEquals(bcryptHashProvider.getAlgorithm(),
                Constants.BCRYPT_HASHING_ALGORITHM);
    }
}
