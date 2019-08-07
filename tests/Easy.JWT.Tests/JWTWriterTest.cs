using System;
using System.Collections.Generic;
using System.IO;
using FluentAssertions;
using Xunit;

namespace Easy.JWT.Tests
{
    public class JWTWriterTest
    {
        [Fact]
        public void WriteSymmetric_ValidArgs_ShouldReturnAValidJWT()
        {
            // GIVEN a valid JWTWriter, issuer, audience, sharedKey and some claims
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";
            var claims = new Dictionary<string, object>
            {
                { "some-claim-int", 123456 },
                { "some-claim-bool", false },
                { "some-claim-array", new string[] { "item1", "item2" }}
            };

            // WHEN writing the JWT
            var jwt = sut.WriteSymmetric(issuer, audience, DateTime.MaxValue, sharedKey, claims);

            // THEN the JWT is the expected one
            var expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJzb21lLWNsYWltLWFycmF5IjpbIml0ZW0xIiwiaXRlbTIiXSwiZXhwIjoyNTM0MDIzMDA4MDAsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.jGjRCItE2n42ZUu7h4GzH-oT8n1Y5wjzs73NYQUcmJk";
            jwt.Should().Be(expected);
        }
        
        [Fact]
        public void WriteSymmetric_EmptySharedKey_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, issuer, audience and an empty sharedKey
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "";

            // WHEN writing the JWT
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.MaxValue, sharedKey, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(sharedKey));
        }
        
        [Fact]
        public void WriteSymmetric_ShortSharedKey_ShouldThrowArgumentOutOfRangeException()
        {
            // GIVEN a valid JWTWriter, issuer, audience and an empty sharedKey
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var sharedKey = "1234";

            // WHEN writing the JWT
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.MaxValue, sharedKey, null);

            // THEN it should throw ArgumentOutOfRangeException
            act.Should().Throw<ArgumentOutOfRangeException>();
        }
        
        [Fact]
        public void WriteSymmetric_EmptyIssuer_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, sharedKey, audience and an empty issuer
            var sut = new JWTWriter();
            var issuer = "";
            var audience = "some-audience";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";

            // WHEN writing the JWT
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.MaxValue, sharedKey, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(issuer));
        }
        
        [Fact]
        public void WriteSymmetric_EmptyAudience_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, sharedKey, issuer and an empty audience
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "";
            var sharedKey = "b7vUtYUvmR46ifoddrccuWCHeRMfm2qw";

            // WHEN writing the JWT
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.MaxValue, sharedKey, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(audience));
        }
        
        [Fact]
        public void WriteAsymmetric_ValidArgs_ShouldReturnAValidJWT()
        {
            // GIVEN a valid JWTWriter, issuer, audience, privateRSAKey path and some claims
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var privateRSAKey = "keys/jwtRS512.key";
            var claims = new Dictionary<string, object>
            {
                { "some-claim-int", 123456 },
                { "some-claim-bool", false }
            };

            // WHEN writing the JWT
            var jwt = sut.WriteAsymmetric(issuer, audience, DateTime.MaxValue, privateRSAKey, claims);

            // THEN the JWT is the expected one
            var expected = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJleHAiOjI1MzQwMjMwMDgwMCwiaXNzIjoic29tZS1pc3N1ZXIiLCJhdWQiOiJzb21lLWF1ZGllbmNlIn0.R9uIuWawfd8hXULqoFpRoFAX2qHmjp7HQFQxllewu7Be9Z8G8WHr8qz-XfmC2GRh-ZP-MzkAkdYzuk_oGrI19WeYim91bHkgIxmEz30WSc_0nlFPoygYKRcBzFs6BI-HPpiOKhiScIN_QEiw0L83r7hV18HA_rwvF7ph1rSilIwhmloBxfTgRrq3yn2h2nshJ05poQrq64_0BBT2yJzcLbbhvuvdMUvEPJ7TiujJq1nyT-yq0072BiSUKwrf7zRZ_xsFhQCZjK8dYfhLlk0PdRB8S2BKIJfcIJhOauKDIRnH7uSbsmLhGMk2H-xSAG7y67iUdWJuJiQVQyefXp9jOVzExUcXmrfs30mYy07VaK1pCcvExoBy7RvmRtXzKWlZfWMrDqeginbJtRzXjtaLp-2CWt0JFE2rUtILLNOSOvMfwv_W53xi72kpchiP_7RKqM7WejSAjYf_jCL3g3mIYl0cDBxSXgdFAmAdZIT7XA6Qf91beBZQw0wBswR6oAHb0Z0C3A8FzdHoQvb07y1EiTqJ7bp8qiw155C34X3HDL1eEjHxP50xe4NPXYBSHf0lOFZ0W_TrcIqwVcJGgkoERgPttLdQH_FHdIlHRs3flcZ3uLuRuU8tmV8wrGrM-xf5mA9ic_668o1619SoWolqATD1gzfXEQcfpvntznIe1-0";
            jwt.Should().Equals(expected);
        }
        
        [Fact]
        public void WriteAsymmetric_EmptyPrivateRSAKeyPath_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, issuer, audience and an empty privateRSAKey
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var privateRSAKeyPath = "";

            // WHEN writing the JWT
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.MaxValue, privateRSAKeyPath, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>();
        }
        
        [Fact]
        public void WriteAsymmetric_InvalidPrivateRSAKeyPath_ShouldThrowIOException()
        {
            // GIVEN a valid JWTWriter, issuer, audience and an empty privateRSAKey
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "some-audience";
            var privateRSAKeyPath = "asdasd";

            // WHEN writing the JWT
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.MaxValue, privateRSAKeyPath, null);

            // THEN it should throw IOException
            act.Should().Throw<IOException>()
                .And.Message.Should().Contain(privateRSAKeyPath);
        }
        
        [Fact]
        public void WriteAsymmetric_EmptyIssuer_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, audience, privateRSAKey path and an empty issuer
            var sut = new JWTWriter();
            var issuer = "";
            var audience = "some-audience";
            var privateRSAKeyPath = "keys/jwtRS512.key";

            // WHEN writing the JWT
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.MaxValue, privateRSAKeyPath, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(issuer));
        }
        
        [Fact]
        public void WriteAsymmetric_EmptyAudience_ShouldThrowArgumentNullException()
        {
            // GIVEN a valid JWTWriter, issuer, privateRSAKey path and an empty audience
            var sut = new JWTWriter();
            var issuer = "some-issuer";
            var audience = "";
            var privateRSAKeyPath = "keys/jwtRS512.key";

            // WHEN writing the JWT
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.MaxValue, privateRSAKeyPath, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(audience));
        }
    }
}