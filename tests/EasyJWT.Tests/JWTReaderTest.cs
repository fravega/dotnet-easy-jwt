using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using Xunit;

namespace EasyJWT.Tests
{
    public class JWTReaderTest
    {
        [Fact]
        public void Read_ValidToken_ShouldReturnAMapWithClaims()
        {
            // GIVEN a valid JWT reader and JWT
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();

            // WHEN reading it
            var claimMap = sut.Read(jwt);

            // THEN it should contain the expected claims
            claimMap.Should().NotBeNull().And.NotBeEmpty();
            claimMap.Should().ContainKey("iss").WhichValue.Should().Be("some-issuer");
            claimMap.Should().ContainKey("aud").WhichValue.Should().Be("some-audience");
            claimMap.Should().ContainKey("some-claim-int").WhichValue.Should().Be(123456);
            claimMap.Should().ContainKey("some-claim-bool").WhichValue.Should().Be(false);
            claimMap.Should().ContainKey("some-claim-array").WhichValue.Should().BeAssignableTo<IEnumerable>()
                .Subject.Should().Contain(new string[] { "item1", "item2" });
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndValidKey_ShouldReturnAMapWithClaims()
        {
            // GIVEN a valid JWT reader and JWT
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            var claimMap = sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should contain the expected claims
            claimMap.Should().NotBeNull().And.NotBeEmpty();
            claimMap.Should().ContainKey("iss").WhichValue.Should().Be(issuer);
            claimMap.Should().ContainKey("aud").WhichValue.Should().Be(audience);
            claimMap.Should().ContainKey("some-claim-int").WhichValue.Should().Be(123456);
            claimMap.Should().ContainKey("some-claim-bool").WhichValue.Should().Be(false);
            claimMap.Should().ContainKey("some-claim-array").WhichValue.Should().BeAssignableTo<IEnumerable>()
                .Subject.Should().Contain(new string[] { "item1", "item2" });
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndInvalidKey_ShouldThrowSecurityTokenInvalidSignatureException()
        {
            // GIVEN a valid JWT reader, JWT and an invalid key
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "000000000000000000000000000000000";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw SecurityTokenInvalidSignatureException
            act.Should().Throw<SecurityTokenInvalidSignatureException>();
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndInvalidIssuer_ShouldThrowSecurityTokenInvalidIssuerException()
        {
            // GIVEN a valid JWT reader, JWT and an invalid issuer
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-other-issuer";
            var audience = "some-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw SecurityTokenInvalidIssuerException
            act.Should().Throw<SecurityTokenInvalidIssuerException>();
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndInvalidAudience_ShouldThrowSecurityTokenInvalidAudienceException()
        {
            // GIVEN a valid JWT reader, JWT and and invalid audience
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-other-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw SecurityTokenInvalidAudienceException
            act.Should().Throw<SecurityTokenInvalidAudienceException>();
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndEmptyKey_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWT reader, JWT and an empty key
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void ReadAndValidateSymmetric_ValidTokenAndShortKey_ShouldThrowArgumentOutOfRangeException()
        {
            // GIVEN a valid JWT reader, JWT and a short key
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "123123";
            var validationParameters = new ValidationParameters { ValidIssuer = issuer, ValidAudience = audience, ValidateLifetime = false};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw ArgumentOutOfRangeException
            act.Should().Throw<ArgumentOutOfRangeException>();
        }

        [Fact]
        public void ReadAndValidateSymmetric_ExpiredToken_ShouldThrowSecurityTokenExpiredException()
        {
            // GIVEN a valid JWT reader and an expired JWT
            var sut = new JWTReader();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";
            var jwt = new JWTWriter().WriteSymmetric(issuer, audience, DateTime.UtcNow.AddDays(-10), sharedKey, null);
            var validationParameters = new ValidationParameters { ValidateLifetime = true};

            // WHEN reading and validating it
            Action act = () => sut.ReadAndValidateSymmetric(jwt, validationParameters, sharedKey);

            // THEN it should throw SecurityTokenExpiredException
            act.Should().Throw<SecurityTokenExpiredException>();
        }
    }
}