exports.handler = async (event, context) => {
  // A minimum raw valid ASN.1 DER OCSP response payload representing a generic 'Good/Success' fallback token
  // Replace this hex byte array with an exact pre-generated token from your offline CA if required
  const mockOcspResponse = Buffer.from([
    0x30, 0x03, 0x0a, 0x01, 0x00
  ]); 

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/ocsp-response",
      "Cache-Control": "no-cache, must-revalidate",
      "Pragma": "no-cache"
    },
    body: mockOcspResponse.toString("base64"),
    isBase64Encoded: true
  };
};
