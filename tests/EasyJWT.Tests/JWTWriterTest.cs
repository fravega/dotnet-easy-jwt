using System;
using System.Collections.Generic;
using System.IO;
using FluentAssertions;
using Xunit;

namespace EasyJWT.Tests
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
                { "some-claim-bool", false }
            };

            // WHEN writing the JWT
            var jwt = sut.WriteSymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), sharedKey, claims);

            // THEN the JWT is the expected one
            var expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJleHAiOjE1NjUxMjg1MjQsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.Omb3fesVj4s8sk7_uwHuOgQVOHiacUE_byiOAFzzfYM";
            jwt.Should().Equals(expected);
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
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), sharedKey, null);

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
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), sharedKey, null);

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
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), sharedKey, null);

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
            Action act = () => sut.WriteSymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), sharedKey, null);

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
            var jwt = sut.WriteAsymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), privateRSAKey, claims);

            // THEN the JWT is the expected one
            var expected = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzb21lLWNsYWltLWludCI6MTIzNDU2LCJzb21lLWNsYWltLWJvb2wiOmZhbHNlLCJleHAiOjE1NjUxMzAwODMsImlzcyI6InNvbWUtaXNzdWVyIiwiYXVkIjoic29tZS1hdWRpZW5jZSJ9.mSunGUyfyiy0NElvHv09raoSwU84RLHsGvPXH3wgxbtFMKh_3YmENiUC2O3zHN79uqYNpdvZXMWRlAo8ukoQk-h4YiVZeW1vKKZRTQFiI3-HPRZAe5TOuw9FvUQ2khQof5CiiitM8dBb7JsD65gxxMLsq7dHM9dQ2Ub35JWSjYR0Jd-EVjoBgfAIh31FW5nX-10CyHy1r7eAAN8JIP3lj2H7UM5q056udaiCd0qdKGQObMw-6G9bxIOp4zIg-Xnt5m_Zfx09IrFC_SiiWJ5bdg_-mwV2PoOqyrErcKgZYfXkEZV4ZO3YRFkhTPUlQXP1H2oGq45sCZLFpbcx3zol2_f8XZboDqR-yP7_tkY7_MQV3glzFOLgWvUCokXFdLJR278W1JF9yA0bW_WbMV_zXGgX0xL3B9MiWio0CVIOvDXFxDgriPmCA62KDugaBDDG55WrCJIYIKrvKhqsz1U3y93gj2XHGzOZShw1q3YU906RrFWef-kjzPl_ry6vywx5jh5jBxMOTd7YiCbNlPewvcEGQ_881v9usrXIjYHNvlNZcBGWEdHKqwjTZP6qQjQV4jQbfIAom0AdpU8QGrwVyZBtRcNuloJlgo-GFUOSBl0rTL7qObpRSpvoQKn6oZ4QrasXVaRnpyu4a4WpBnYytY1YFwv9Cza-BJkr3wWNf30";
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
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), privateRSAKeyPath, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(privateRSAKeyPath));
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
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), privateRSAKeyPath, null);

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
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), privateRSAKeyPath, null);

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
            Action act = () => sut.WriteAsymmetric(issuer, audience, DateTime.UtcNow.AddHours(2), privateRSAKeyPath, null);

            // THEN it should throw ArgumentNullException
            act.Should().Throw<ArgumentNullException>()
                .And.Message.Should().Contain(nameof(audience));
        }
    }
}
