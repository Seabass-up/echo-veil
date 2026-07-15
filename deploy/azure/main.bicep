targetScope = 'resourceGroup'

@description('Azure region selected for the AMD SEV-SNP confidential VM.')
param location string = 'eastus2'

@description('Stable deployment prefix.')
@minLength(3)
@maxLength(20)
param prefix string = 'echo-veil'

@description('Linux administrator public key. SSH is not exposed by the NSG.')
param adminSshPublicKey string

@description('Linux administrator name. SSH is not exposed by the NSG.')
param adminUsername string = 'echoadmin'

@description('Confidential VM SKU. Confirm subscription quota before deployment.')
param vmSize string = 'Standard_DC2as_v5'

var unique = uniqueString(subscription().id, resourceGroup().id)
var vmName = '${prefix}-cvm'
var vaultName = take(replace('${prefix}-${unique}', '-', ''), 24)

resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-https-mtls'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.42.0.0/16']
    }
    subnets: [
      {
        name: 'confidential-compute'
        properties: {
          addressPrefix: '10.42.1.0/24'
          networkSecurityGroup: {
            id: networkSecurityGroup.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-public-ip'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: '${prefix}-${unique}'
    }
  }
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: virtualNetwork.properties.subnets[0].id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource confidentialVm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'ConfidentialVM'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys' // privacy-scan:allow -- target VM path
              keyData: adminSshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-confidential-vm-jammy'
        sku: '22_04-lts-cvm'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        caching: 'ReadWrite'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: {
            securityEncryptionType: 'DiskWithVMGuestState'
          }
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
          properties: { primary: true }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: true }
    }
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'premium'
    }
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Enabled'
    accessPolicies: []
  }
}

resource vmReleasePolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-07-01' = {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: confidentialVm.identity.principalId
        permissions: {
          keys: ['get', 'release']
          secrets: []
          certificates: []
          storage: []
        }
      }
    ]
  }
}

output enclavePublicIp string = publicIp.properties.ipAddress
output enclaveFqdn string = publicIp.properties.dnsSettings.fqdn
output confidentialVmName string = confidentialVm.name
output confidentialVmPrincipalId string = confidentialVm.identity.principalId
output keyVaultName string = keyVault.name
