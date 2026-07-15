targetScope = 'resourceGroup'

@description('Existing Premium Key Vault created by main.bicep.')
param keyVaultName string

@description('Exact x-ms-sevsnpvm-launchmeasurement from the approved image attestation JWT.')
@minLength(96)
@maxLength(96)
param approvedLaunchMeasurement string

@description('Shared Microsoft Azure Attestation authority for East US 2.')
param attestationAuthority string = 'https://sharedeus2.eus2.attest.azure.net'

@description('Exportable HSM-backed wrapping key name.')
param keyName string = 'echo-veil-skr-v1'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

var releasePolicy = {
  version: '1.0.0'
  anyOf: [
    {
      authority: attestationAuthority
      allOf: [
        {
          claim: 'x-ms-isolation-tee.x-ms-attestation-type'
          equals: 'sevsnpvm'
        }
        {
          claim: 'x-ms-isolation-tee.x-ms-compliance-status'
          equals: 'azure-compliant-cvm'
        }
        {
          claim: 'x-ms-sevsnpvm-launchmeasurement'
          equals: approvedLaunchMeasurement
        }
        {
          claim: 'x-ms-sevsnpvm-is-debuggable'
          equals: false
        }
      ]
    }
  ]
}

resource secureReleaseKey 'Microsoft.KeyVault/vaults/keys@2022-07-01' = {
  parent: keyVault
  name: keyName
  properties: {
    kty: 'RSA-HSM'
    keySize: 4096
    keyOps: ['encrypt', 'decrypt']
    attributes: {
      enabled: true
      exportable: true
    }
    release_policy: {
      contentType: 'application/json; charset=utf-8'
      data: base64(string(releasePolicy))
    }
  }
}

output secureReleaseKeyId string = secureReleaseKey.properties.keyUriWithVersion
