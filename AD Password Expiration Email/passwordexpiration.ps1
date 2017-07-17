<#
.Synopsis
   Script to Automate Email Reminders when Users Passwords are due to Expire.
.DESCRIPTION
   Script to Automated Email Reminders when Users Passwords due to Expire.
   WindowsServerEssentials.com
   Customized for Discovery by David Solis
   Requires: Windows PowerShell Module for Active Directory
#>
$smtpServer = "dctmail.discovery.com"
$from = "TechKnow_Action@discovery.com" #The "From" E-mail address that users will see
$logging = "true"
$logPath = "c:\logs"
$testing = 
$domains = "int.dci.discovery.com",#"dna.dci.discovery.com","us.dci.discovery.com","dne.dci.discovery.com" #Domains that this script will run against
$notificationdays = 15,10,5,4,3,2,1,0 #Days prior to expiration when users will be notified

###################################################################################################################
$start = [datetime]::Now
# System Settings
$textEncoding = [System.Text.Encoding]::UTF8
$today = [datetime]::Now
# End System Settings

# Get Users From AD who are Enabled, Passwords Expire and are Not Currently Expired
Import-Module ActiveDirectory
$padVal = "20"
Write-Output "Script Loaded"
Write-Output "*** Settings Summary ***"
$smtpServerLabel = "SMTP Server".PadRight($padVal," ")
$domainname = "Domain".PadRight($padVal," ")
$expireInDaysLabel = "Expire in Days".PadRight($padVal," ")
$fromLabel = "From".PadRight($padVal," ")
$testLabel = "Testing".PadRight($padVal," ")
$testRecipientLabel = "Test Recipient".PadRight($padVal," ")
$logLabel = "Logging".PadRight($padVal," ")
$logPathLabel = "Log Path".PadRight($padVal," ")
if($testing)
{
    if(($testRecipient) -eq $null)
    {
        Write-Output "No Test Recipient Specified"
        Exit
    }
}
if($logging)
{
    if(($logPath) -eq $null)
    {
        $logPath = $PSScriptRoot
    }
}
foreach($domain in $domains)
{
Write-Output "$smtpServerLabel : $smtpServer"
Write-Output "$DomainName : $domain"
Write-Output "$expireInDaysLabel : $notificationdays"
Write-Output "$fromLabel : $from"
Write-Output "$logLabel : $logging"
Write-Output "$logPathLabel : $logPath"
Write-Output "$testLabel : $testing"
Write-Output "$testRecipientLabel : $testRecipient"
Write-Output "*".PadRight(25,"*")

$users = get-aduser -server $domain -filter {(Enabled -eq $true) -and (PasswordNeverExpires -eq $false)} -properties Name, PasswordNeverExpires, PasswordExpired, PasswordLastSet, EmailAddress, erp-company, Memberof |`
		where {($_.passwordexpired -eq $false)`
         		-and ($_.EmailAddress -ne $null)`
         		-and [string]$_.'erp-company' -notlike "*Eurosport*"`
				}
# Count Users
$usersCount = ($users | Measure-Object).Count
Write-Output "Found $usersCount User Objects"
# Collect Domain Password Policy Information
$defaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge.Days
Write-Output "Domain Default Password Age: $defaultMaxPasswordAge"
# Collect Users
$colUsers = @()
# Process Each User for Password Expiry
Write-Output "Process User Objects"
foreach ($user in $users)
{
    $Name = $user.Name
    $emailaddress = $user.emailaddress
    $passwordSetDate = $user.PasswordLastSet
    $samAccountName = $user.SamAccountName
    $pwdLastSet = $user.PasswordLastSet
    # Check for Fine Grained Password
    $maxPasswordAge = $defaultMaxPasswordAge
    $PasswordPol = (Get-AduserResultantPasswordPolicy $user)
    if (($PasswordPol) -ne $null)
    {
        $maxPasswordAge = ($PasswordPol).MaxPasswordAge.Days
    }
    $expireson = $pwdLastSet.AddDays($maxPasswordAge)
    $daysToExpire = New-TimeSpan -Start $today -End $Expireson
    # Round Up or Down
    if(($daysToExpire.Days -eq "1") -and ($daysToExpire.Hours -ge "12"))
    {
        # If password expires in 1 day and more than 12 hours, ie 1 day 23 hours, we round up to two days for notification purposes.
        $daysToExpire = 2
    }
    else
    {
        # Use total number of days from from 'Time Span'
        $daysToExpire = $daysToExpire.Days
        if(($daysToExpire) -le "0")
        {
            # if $daystoExpire is negative value reset to 0
            $daysToExpire = 0
        }

    }
    # Create User Object
    $userObj = New-Object System.Object
    $userObj | Add-Member -Type NoteProperty -Name TimeStamp -Value (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt')
    $userObj | Add-Member -Type NoteProperty -Name UserName -Value $samAccountName
    $userObj | Add-Member -Type NoteProperty -Name Name -Value $Name
    $userObj | Add-Member -Type NoteProperty -Name EmailAddress -Value $emailAddress
    $userObj | Add-Member -Type NoteProperty -Name PasswordSet -Value $pwdLastSet
    $userObj | Add-Member -Type NoteProperty -Name DaysToExpire -Value $daysToExpire
    $userObj | Add-Member -Type NoteProperty -Name ExpiresOn -Value $expiresOn
    $colUsers += $userObj
}
$colUsersCount = ($colUsers | Measure-Object).Count
Write-Output "$colusersCount Users processed"
$notifyUsers = $colUsers | where { $_.DaysToExpire -in $notificationdays }
$notifiedUsers = @()
$notifyCount = ($notifyUsers | Measure-Object).Count
Write-Output "$notifyCount Users to notify"
foreach ($user in $notifyUsers)
{
    # Email Address
    $samAccountName = $user.UserName
    $emailAddress = $user.EmailAddress
   # Set Greeting Message
    $image1 = "\\us.dci.discovery.com\software\public\emailimages\gto.png"
    $name = $user.Name
    $daysToExpire = $user.DaysToExpire
    $messageDays = "today."
    if (($daysToExpire) -gt "1")
    {
        $messageDays = "in " + "$daystoexpire" + " days."
    }
    # Subject Setting
    $subject="Your password will expire $messageDays"
    # Email Body Set Here, Note You can use HTML, including Images.
    $body = "
    <body style=""font-family:calibri"">
    <p>Dear <strong> $Name </strong> ,</p>
	<p>Your password will expire in <strong> $daysToExpire </strong> day(s) . You will need to change your password <span style=""text-decoration: underline;""><strong> PRIOR to it expiring </strong></span> to continue logging into your Discovery computer.&nbsp;</p>
    <p><strong> To reset your password before expiration: </strong></p>
    <p style=""padding-left: 30px;""><span style=""text-decoration: underline; color: #0000ff;""><strong> Windows Users </strong></span></p>
    <ol>
    <li>Press <strong> Ctrl </strong> + <strong> Alt </strong> + <strong> Delete </strong></li>
    <li>Click <strong> Change a password </strong></li>
    <li>Follow the on-screen instructions</li>
    </ol>
    <p style=""padding-left: 30px;""><span style=""text-decoration: underline; color: #0000ff;""><strong> Mac Users </strong></span></p>
    <ol>
    <li>Open the <strong> Apple </strong> menu and select <strong> System Preferences </strong></li>
    <li>Click <strong> User &amp; Groups </strong></li>
    <li>Click your name from the left pane</li>
    <li>Click <strong> Change Password </strong></li>
    <li>Follow the on-screen instructions</li>
    </ol>
    <p><span style=""text-decoration: underline;""><strong>Discovery Password Security Policy:</strong></span></p>
    <ul>
    <li>Passwords must contain characters from at least 3 of the following categories:
    <ul>
    <li>uppercase letter</li>
    <li>lowercase letter</li>
    <li>number</li>
    <li>symbol (for example: !, $, #, %)</li>
    </ul>
    </li>
    <li>Passwords must be at least 10 characters long</li>
    <li>New passwords must not be one of your previous 10 passwords</li>
    </ul>
    <p>If you have other devices accessing Discovery systems, you may need to update them with your new password.</p>
    <p>Thanks in advance,</p>
    <p>Your GT&amp;O Support Team</p>
    <p><img src=""gto.png"">
    </P>
    </body>
 "

    # If Testing Is Enabled - Email Administrator
    if($testing)
    {
        $emailaddress = $testRecipient
    } # End Testing

    # If a user has no email address listed
    if(($emailaddress) -eq $null)
    {
        $emailaddress = $testRecipient
    }# End No Valid Email
    $samLabel = $samAccountName.PadRight($padVal," ")
    if($status)
    {
        Write-Output "Sending Email : $samLabel : $emailAddress"
    }
    try
    {
        Send-Mailmessage -smtpServer $smtpServer -from $from -to $emailaddress -subject $subject -body $body -bodyasHTML -priority High -Encoding $textEncoding -ErrorAction Stop -Attachments $image1
        $user | Add-Member -MemberType NoteProperty -Name SendMail -Value "OK"
    }
    catch
    {
        $errorMessage = $_.exception.Message
        if($status)
        {
           $errorMessage
        }
        $user | Add-Member -MemberType NoteProperty -Name SendMail -Value $errorMessage
    }
    $notifiedUsers += $user
}
if($logging)
{
    # Create Log File
    Write-Output "Creating Log File"
    $day = $today.Day
    $month = $today.Month
    $year = $today.Year
    $date = "$month-$day-$year"
    $logFileName = "$date-$domain-PasswordLog.csv"
    if(!($logPath.EndsWith("\")))
    {
       $logFile = $logPath + "\"
    }
    $logFile = $logFile + $logFileName
    Write-Output "Log Output: $logfile"
    $notifiedUsers | Export-CSV $logFile
}
$notifiedUsers | sort DaystoExpire | FT -autoSize
}

$stop = [datetime]::Now
$runTime = New-TimeSpan $start $stop
Write-Output "Script Runtime: $runtime"
# End
