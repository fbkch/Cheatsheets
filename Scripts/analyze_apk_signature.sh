#!/bin/bash
# Script to analyze APK signature details

APK_FILE="$1"

if [ -z "$APK_FILE" ]; then
    echo "Usage: $0 <apk_file>"
    exit 1
fi

echo "SIGNER CERTIFICATE"
echo "================="
echo ""

# Check if the APK is signed
if jarsigner -verify "$APK_FILE" &>/dev/null; then
    echo "Binary is signed"
else
    echo "Binary is NOT signed"
    exit 1
fi

# Check for v1 signature
if unzip -l "$APK_FILE" | grep -q "META-INF/.*\.[RDS]SA\|META-INF/.*\.EC"; then
    echo "v1 signature: True"
else
    echo "v1 signature: False"
fi

# Check for v2, v3, v4 signatures (if apksigner is available)
if command -v apksigner &>/dev/null; then
    APKSIGNER_OUTPUT=$(apksigner verify --verbose "$APK_FILE" 2>&1)
    
    if echo "$APKSIGNER_OUTPUT" | grep -q "v2 scheme"; then
        echo "v2 signature: True"
    else
        echo "v2 signature: False"
    fi
    
    if echo "$APKSIGNER_OUTPUT" | grep -q "v3 scheme"; then
        echo "v3 signature: True"
    else
        echo "v3 signature: False"
    fi
    
    if echo "$APKSIGNER_OUTPUT" | grep -q "v4 scheme"; then
        echo "v4 signature: True"
    else
        echo "v4 signature: False"
    fi
else
    echo "apksigner not found, cannot verify v2/v3/v4 signatures definitively"
fi

# Extract certificate details
echo ""
echo "Certificate Details:"
echo "==================="

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Extract the certificate
unzip -q "$APK_FILE" "META-INF/*.RSA" "META-INF/*.DSA" "META-INF/*.EC" -d "$TEMP_DIR" 2>/dev/null
CERT_FILE=$(find "$TEMP_DIR/META-INF" -name "*.RSA" -o -name "*.DSA" -o -name "*.EC" | head -1)

if [ -n "$CERT_FILE" ]; then
    # Extract the certificate details using keytool
    keytool -printcert -file "$CERT_FILE" | while IFS= read -r line; do
        if [[ "$line" == *"Owner:"* ]]; then
            SUBJECT=${line#*Owner: }
            echo "X.509 Subject: $SUBJECT"
        elif [[ "$line" == *"Signature algorithm"* ]]; then
            SIG_ALG=${line#*Signature algorithm: }
            echo "Signature Algorithm: $SIG_ALG"
        elif [[ "$line" == *"Valid from:"* ]]; then
            VALID_FROM=${line#*Valid from: }
            VALID_TO=${line#*until: }
            echo "Valid From: $VALID_FROM"
            echo "Valid To: $VALID_TO"
        elif [[ "$line" == *"Issuer:"* ]]; then
            ISSUER=${line#*Issuer: }
            echo "Issuer: $ISSUER"
        elif [[ "$line" == *"Serial number:"* ]]; then
            SERIAL=${line#*Serial number: }
            echo "Serial Number: $SERIAL"
        fi
    done
    
    # Calculate certificate hashes
    echo ""
    echo "Certificate Fingerprints:"
    echo "======================="
    openssl x509 -inform DER -in "$CERT_FILE" -outform PEM -out "$TEMP_DIR/cert.pem" 2>/dev/null
    
    echo "Hash Algorithm: sha256"
    echo "md5: $(openssl x509 -in "$TEMP_DIR/cert.pem" -fingerprint -md5 -noout | cut -d "=" -f 2 | tr -d ':')"
    echo "sha1: $(openssl x509 -in "$TEMP_DIR/cert.pem" -fingerprint -sha1 -noout | cut -d "=" -f 2 | tr -d ':')"
    echo "sha256: $(openssl x509 -in "$TEMP_DIR/cert.pem" -fingerprint -sha256 -noout | cut -d "=" -f 2 | tr -d ':')"
    
    # Get public key info
    echo ""
    echo "Public Key Information:"
    echo "======================"
    openssl x509 -in "$TEMP_DIR/cert.pem" -noout -text | grep -A 1 "Public Key Algorithm" | while IFS= read -r line; do
        if [[ "$line" == *"Public Key Algorithm"* ]]; then
            PK_ALG=${line#*Public Key Algorithm: }
            echo "PublicKey Algorithm: $PK_ALG"
        elif [[ "$line" == *"bit"* ]]; then
            BIT_SIZE=$(echo "$line" | grep -o '[0-9]\+')
            echo "Bit Size: $BIT_SIZE"
        fi
    done
else
    echo "No certificate file found in META-INF directory"
fi
