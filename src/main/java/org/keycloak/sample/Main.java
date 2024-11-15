package org.keycloak.sample;

import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JsonSerialization;

public class Main {

    private static void testRsa() throws Exception {
        JWKParser rsaParser = JWKParser.create().parse(
                "{\n"
                + "      \"kid\": \"FbETpDC0k3f83WCe3j4qVL34E3jamhiea9N5aCophBE\",\n"
                + "      \"kty\": \"RSA\",\n"
                + "      \"alg\": \"RS256\",\n"
                + "      \"use\": \"sig\",\n"
                + "      \"x5c\": [\n"
                + "        \"MIICmzCCAYMCBgGR61ktBDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwOTEzMTIyNDM1WhcNMzQwOTEzMTIyNjE1WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUW8v+DjbwfW2SCxH9JcG/qF0dnEVAgAiy6OkYshxFsCm8ZHyFoFOai4nJqZsV9ljta09m7fdojxJPWnCYqI51SsZWFWcadMrQDNPOHvN4axdd7TGAXgjcIXkJtVIoHm55kuiCMPRohGTKSYy0cqnt3Kb7u1GejMXsAMYcFQAkxGQGOGNt/ruZtWjImubK6DSrJbhdvNcti/xPbyKMC9EuqhTfGtIjODl5P+oaWUluF1yWOLvC2LxUob2cGtlKs0x9N93LwCq8D8jqz2zXO9+lYr5aBoVoOwLa7I//hd9A+gmjtlSrzecNxhruvRhnzZTwQE8kPcAdBNCFPa103ipLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAClBUPZt4rmgsQ6GJISKevFeR1L4de05qfYP5sOssSwPKLea8qXK5YNKCBANEp0WM7GBz1q9dTjMRED8y7dWeiQh9e7tudy6op6+FB5sYvLYjGXTi3SAhGCXyJ8uq5227EQpe1z4/s9JDXisqcva+bROckWjEHIm8Lm9Af2i1+kXvShz5f1vTCpbbX4UqJPTLRM1jKuR1sTGWnR2hQRNxp6uhQFQ3lgyGCEOV1Za0TSUemkqCO60gByC7beIdTQkCuHQhE+pTcv5tm4Y2CKAUVSIK74ALmU3dFHCXSymg2qXNqztSEjxN6+IJbHzF24ChGb7Y1tgSdNX4uqo1hPKf50=\"\n"
                + "      ],\n"
                + "      \"x5t\": \"dCw8NQwGR1Md0RgLjwegHeNhTzE\",\n"
                + "      \"x5t#S256\": \"FLBAgUNNNJQpoNpwJx-TF13GkmsNczhExb7412m-pY8\",\n"
                + "      \"n\": \"lFvL_g428H1tkgsR_SXBv6hdHZxFQIAIsujpGLIcRbApvGR8haBTmouJyambFfZY7WtPZu33aI8ST1pwmKiOdUrGVhVnGnTK0AzTzh7zeGsXXe0xgF4I3CF5CbVSKB5ueZLogjD0aIRkykmMtHKp7dym-7tRnozF7ADGHBUAJMRkBjhjbf67mbVoyJrmyug0qyW4XbzXLYv8T28ijAvRLqoU3xrSIzg5eT_qGllJbhdclji7wti8VKG9nBrZSrNMfTfdy8AqvA_I6s9s1zvfpWK-WgaFaDsC2uyP_4XfQPoJo7ZUq83nDcYa7r0YZ82U8EBPJD3AHQTQhT2tdN4qSw\",\n"
                + "      \"e\": \"AQAB\"\n"
                + "}"
        );
        System.err.println("Supported RSA: " + rsaParser.isKeyTypeSupported("RSA"));
        System.err.println(rsaParser.toPublicKey());
        JWK rsa = JWKBuilder.create()
                .kid(rsaParser.getJwk().getKeyId())
                .algorithm(rsaParser.getJwk().getAlgorithm())
                .rsa(rsaParser.toPublicKey());
        System.err.println(JsonSerialization.writeValueAsString(rsa));
    }

    private static void testEdEC() throws Exception {
        JWKParser ecdcParser = JWKParser.create().parse(
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\n"
                + "   \"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\n"
                + "   \"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}");
        System.err.println("Supported OKP: " + ecdcParser.isKeyTypeSupported("OKP"));
        System.err.println(ecdcParser.toPublicKey());
        JWK eced = JWKBuilder.create()
                .kid(ecdcParser.getJwk().getKeyId())
                .algorithm(ecdcParser.getJwk().getAlgorithm())
                .okp(ecdcParser.toPublicKey());
        System.err.println(JsonSerialization.writeValueAsString(eced));
    }

    public static void main(String... args) throws Exception {
        testRsa();
        testEdEC();
    }
}
