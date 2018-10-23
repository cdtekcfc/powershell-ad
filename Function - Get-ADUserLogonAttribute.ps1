
<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2016 v5.3.130
	 Created on:   	3/1/2018
	 Created by:    +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
                    |C|H|R|I|S|T|I|A|N| |D|E|L|G|A|D|O|
                    ++-+-+-+-+-+-+++-+-+-+-+-+-+-+-+-++
                     |A|C|T|I|V|E| |D|I|R|E|C|T|O|R|Y| 
                     +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>


<#
	.SYNOPSIS
		This function queries the SamAccountname attribute in all DCs in the domain, retreiving attributes used to determine the user's most recent logon activity.
	
	.DESCRIPTION
		- -VerifyDC switch to verify the DCs that will be queried are available.
		- Supports multiple input values by pipeline.
	
	.PARAMETER SamAccountName
		A description of the SamAccountName parameter.
	
	.PARAMETER Domain
		The domain to which you want to search the username in.
	
	.PARAMETER VerifyDC
		When searching more than one userid, this switch parameter will ignore any DCs that fail to return a response in the first search. 
        This is to avoid using DCs that are not responding.
	
	.PARAMETER ShowMostRecentOnly
		This switch parameter will only output the object with the most recent 'LastLogon' value. The function will continue to query all of the DCs in the domain
        but only the one with the most recent 'LastLogon' value will be displayed.

	
	.EXAMPLE
		Get-ADUserLogonAttribute -SamAccountName marty.byrde
		
		Queries all DCs in the domain from which the user running the script belongs to, searching for a SamAccountName that has 'marty.byrde' as its value.
	
	.EXAMPLE
		Get-ADUserLogonAttribute -SamAccountName marty.byrde -Domain lab01.cfctek01.org
		
		Queries all DCs in domain "lab01.cfctek01.org" for a user that has 'marty.byrde' as the SamAccountName.
	
	.EXAMPLE
		Get-Content C:\files\Users.txt | Get-ADUserLogonAttribute
		
		Queries all DCs in the domain from which the user running the script belongs to, searching for all values inside "C:\Files\Users.txt"
	
	.EXAMPLE
		Get-Content C:\files\Users.txt | Get-ADUserLogonAttribute -VerifyDC
		
		Queries all DCs in the domain from which the user running the script belongs.
		Verifies if each DC is available before processing the values in C:\Files\Users.txt
    
    .EXAMPLE
	    Get-ADUserLogonAttribute -SamAccountName marty.byrde -ShowMostRecentOnly
        
        Queries all DCs in the domain from which the user running the script belongs but will only show the result from the DC with the most recent 'LastLogon' value.

	.NOTES
		Additional information about the function.
		Created by: 
		|C|H|R|I|S|T|I|A|N| |D|E|L|G|A|D|O|
		++-+-+-+-+-+-+++-+-+-+-+-+-+-+-+-++
		|A|C|T|I|V|E| |D|I|R|E|C|T|O|R|Y|
#>
function Get-ADUserLogonAttribute
{
	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		[array]$SamAccountName = $env:USERNAME,
		[string]$Domain = $env:USERDNSDOMAIN,
		[switch]$VerifyDC,
		[switch]$ShowMostRecentOnly
	)
	
	Begin
	{
		Write-Verbose "Starting ""Begin"""
		Write-Verbose "Loading Function ""CheckAndLoad-Module"""
		
		#START - Verifying ActiveDirectory Module is present#
		
		Function CheckAndLoad-Module
		{
			[CmdletBinding()]
			param
			(
				[Parameter(ValueFromPipeline = $true)]
				[string[]]$ModuleName
			)
			
			Begin
			{
				
				
				
			}
			
			Process
			{
				
				Foreach ($MN in $ModuleName)
				{
					
					Write-Verbose "Checking if Module $MN is loaded"
					$Check_Module_AD = Get-Module -Name $MN
					
					if ($Check_Module_AD.Name -ne $MN)
					{
						
						
						try
						{
							
							Write-Verbose "Module was not loaded, attempting to load module: $MN"
							Import-Module -Name $MN -ErrorAction Stop -ErrorVariable STATUS_ERROR
							Write-Verbose "$MN was loaded"; [array]$Result += "Success: Module was loaded : $MN"
							
						}
						
						catch [Exception]
						
						{
							
							switch -regex ($_.Exception)
							{
								"The specified module 'DNSClient' was not loaded because no valid module file was found in any module directory."   { Write-Verbose "ERROR: Module not Installed: $MN"; [array]$Result += "Error: Module is not Insalled : $MN - (Only Available in Windows 8 and Up)" }
								"The specified module '$MN' was not loaded because no valid module file was found in any module directory."         { Write-Verbose "ERROR: Module not Installed: $MN"; [array]$Result += "Error: Module is not Insalled : $MN" }
								default { Write-Verbose "ERROR: Unknown Error: $MN"; [array]$Result = "Error: Unknown Error : $MN" }
								
								
								
							}
							
						}
						
						finally { }
						
						
					}
					
					
					elseif ($Check_Module_AD.Name -eq $MN)
					{ Write-Verbose "$MN is already installed"; [array]$Result += "Success: Module is loaded already : $MN" }
					
					else { }
					
					
					
				}
				
			}
			
			
			
			End
			{
				
				$Result
				
			}
		}
		
		Write-Verbose "Running Function ""CheckAndLoad-Module"" to verify and load the ActiveDirectory PS Module"
		$ModuleCheck = CheckAndLoad-Module -ModuleName ActiveDirectory
		
		
		if ($ModuleCheck -like "*error*") { $ModuleCheck; break }
		
		#END - Verifying ActiveDirectory Module is present
		
		#START - Get List of DCs 
		Try
		{
			
			Write-Verbose "Searching for all Domain Controllers in ""$Domain"""
			$DCList = Get-ADDomainController -Filter * -Server $Domain -ErrorVariable ERROR_DCList -ErrorAction Stop
			
		}
		
		Catch [exception]
		
		{
			
			Switch -Regex ($_.Exception)
			{
				
				Default { $ERROR_CATCH_DCList = $ERROR_DCList.ErrorRecord.Exception }
				
			}
			
		}
		
		Finally
		{
			if ($DCList -ne $null -and $ERROR_CATCH_DCList -eq $null)
			{
				Write-Verbose "Results were returned from Get-ADDomainController"
				#Script Continues
			}
			
			elseif ($DCList -eq $null -and $ERROR_CATCH_DCList -eq $null)
			{
				Write-Verbose "No Results were returned when running Get-ADDomainController"
				Throw "ERROR - No Results were returned when running Get-ADDomainController"
				#Script Stops
			}
			
			elseif ($ERROR_CATCH_DCList -ne $null)
			{
				Write-Verbose "Errors were returned when running Get-ADDomainController"
				Throw $ERROR_CATCH_DCList
				#Script Stops
			}
			
			else
			{
				Write-Verbose "Other Error! Conditions not met"; Throw "ERROR - Unknown ERROR when attempting to run Get-ADDomainController" #Script Stops }
			}
			
			
			
			
		}
		#END - Get List of DCs
		
		#START - Verification Process for every DC discovered in the domain before querying each user against it
		if ($VerifyDC)
		{
			
			#Verifying each DC returned
			Write-Warning "Verifying all ""$($DCList.Count)"" DCs from ""$Domain"" before starting search."
			Write-Verbose "Verifying all ""$($DCList.Count)"" DCs Returned"
			
			foreach ($DC in $DCList)
			{
				Try
				{
					Write-Verbose "Verifying DC ""$($DC.HostName)"""
					$VerifyDC = Get-ADUser -Identity $Env:USERNAME -Server $DC.HostName -ErrorVariable ERROR_VerifyDC -ErrorAction Stop
					
				}
				
				Catch [exception]
				
				{
					
					Switch -Regex ($_.Exception)
					{
						
						Default { $ERROR_CATCH_VerifyDC = $ERROR_VerifyDC.ErrorRecord.Exception }
						
					}
					
				}
				
				Finally
				{
					if ($VerifyDC -ne $null -and $ERROR_CATCH_VerifyDC -eq $null)
					{
						[array]$VerifiedDCList += [pscustomobject]@{
							
							DCState  = "OK"
							HostName = "$($DC.HostName)"
							IPV4Address = "$($DC.IPv4Address)"
							Site	 = "$($DC.Site)"
						}
					}
					
					elseif ($Verify -eq $null -or $ERROR_CATCH_VerifyDC -eq $null)
					{
						Write-Verbose "No results or Errors were returned when verifying DC ""$($DC.HostName)"" by searching for ""$env:USERNAME"""
						
						[array]$VerifiedDCList += [pscustomobject]@{
							
							DCState  = "Failed"
							HostName = "$($DC.HostName)"
							IPV4Address = "$($DC.IPv4Address)"
							Site	 = "$($DC.Site)"
						}
					}
					
					else
					{
						
						Write-Verbose "Other Error while verifying DC ""$($DC.HostName)"" by searching for ""$env:USERNAME"""
						
						[array]$VerifiedDCList += [pscustomobject]@{
							
							DCState  = "Failed"
							HostName = "$($DC.HostName)"
							IPV4Address = "$($DC.IPv4Address)"
							Site	 = "$($DC.Site)"
						}
					}
					
					
				}
			}
			
		}
		
		else { Write-Verbose "VerifyDC Skipped" }
		#END - Verification Process for every DC discovered in the domain before querying each user against it
	}
	Process
	{
		
		Write-Verbose "Starting ""Process"""
		
		#START - Querying all Discovered/Verified DCs for each SamAccount Name
		foreach ($User in $SamAccountName)
		{
			clv ConsolidatedResultsForUser -ErrorAction SilentlyContinue
			
			if ($VerifyDC)
			{
				Write-Verbose "Starting Query for user ""$User"" against every verified DC"
				foreach ($VerifiedDC in $VerifiedDCList)
				{
					
					
					#Check if User Exists.
					if ($ERROR_CATCH_UserInfo -ne "User was not Found")
					{
						if ($VerifiedDC.DCState -eq "OK")
						{
							
							#if ($ERROR_CATCH_UserInfo -ne "User was not Found")
							#{
							
							Try
							{
								
								clv ERROR_CATCH_UserInfo -ErrorAction SilentlyContinue
								Write-Verbose "Checking on User ""$User"" with DC ""$($VerifiedDC.HostName)"""
								
								$UserInfo = Get-ADUser -Identity $User -Server $VerifiedDC.HostName `
													   -Properties GivenName, SurName, Name, DisplayName, LastLogon, LastLogonDate, Enabled, LastBadPasswordAttempt, PasswordLastSet, mail, WhenCreated, WhenChanged -ErrorVariable ERROR_UserInfo -ErrorAction Stop | `
								Select-Object GivenName, SurName, Name, DisplayName, Enabled, SamAccountName, @{ N = 'LastLogon'; E = { [DateTime]::FromFileTime($_.LastLogon) } }, `
											  LastLogonDate, lastLogonTimestamp, LastBadPasswordAttempt, PasswordLastSet, @{ n = 'OU'; E = { $_.distinguishedname -replace '^.+?,(CN|OU.+)', '$1' } }, mail, WhenCreated, WhenChanged
								
							}
							
							Catch [exception]
							
							{
								
								Switch -Regex ($_.Exception)
								{
									
									"Cannot find an object with identity: " { $ERROR_CATCH_UserInfo = "User was not Found" }
									Default { $ERROR_CATCH_UserInfo = $ERROR_UserInfo.ErrorRecord.Exception.Message }
									
								}
								
							}
							
							Finally
							{
								if ($ShowMostRecentOnly)
								{
									Write-Verbose "The ""ShowMostRecentOnly"" Parameter was used"
									if ($UserInfo -ne $null -and $ERROR_CATCH_UserInfo -eq $null)
									{
										
										Write-Verbose "Results were returned from when searching for user ""$User"""
										[array]$ConsolidatedResultsForUser+=[pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = $UserInfo.SamAccountName
											UserName = $User
											GivenName = $UserInfo.GivenName
											SurName = $UserInfo.SurName
											DisplayName = $UserInfo.DisplayName
											Enabled = $UserInfo.Enabled
											PasswordLastSet = $UserInfo.PasswordLastSet
											LastLogon = $UserInfo.LastLogon
											LastLogonDate = $UserInfo.LastLogonDate
											Mail = $UserInfo.mail
											WhenCreated = $UserInfo.WhenCreated
											WhenChanged = $UserInfo.WhenChanged
											OU = $UserInfo.OU
										}
										
									}
									
									elseif ($UserInfo -eq $null -and $ERROR_CATCH_UserInfo -eq $null)
									{
										Write-Verbose "NO Results were returned when searching for user ""$User"""
										[array]$ConsolidatedResultsForUser += [pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = "N/A - No Results were returned"
											UserName = $User
											GivenName = "N/A - No Results were returned"
											SurName = "N/A - No Results were returned"
											DisplayName = "N/A - No Results were returned"
											Enabled = "N/A - No Results were returned"
											PasswordLastSet = "N/A - No Results were returned"
											LastLogon = "N/A - No Results were returned"
											LastLogonDate = "N/A - No Results were returned"
										}
									}
									
									elseif ($ERROR_CATCH_UserInfo -ne $null)
									{
										Write-Verbose "ERRORs were returned when searching for user ""$User"""
										[array]$ConsolidatedResultsForUser += [pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = $ERROR_CATCH_UserInfo
											UserName = $User
											GivenName = $ERROR_CATCH_UserInfo
											SurName = $ERROR_CATCH_UserInfo
											DisplayName = $ERROR_CATCH_UserInfo
											Enabled = $ERROR_CATCH_UserInfo
											PasswordLastSet = $ERROR_CATCH_UserInfo
											LastLogon = $ERROR_CATCH_UserInfo
											LastLogonDate = $ERROR_CATCH_UserInfo
											Mail = $ERROR_CATCH_UserInfo
											WhenCreated = $ERROR_CATCH_UserInfo
											WhenChanged = $ERROR_CATCH_UserInfo
											OU = $ERROR_CATCH_UserInfo
										}
										if ($ERROR_CATCH_UserInfo -eq "User was not Found") { Write-Warning "User ""$User"" was not found in ""$($VerifiedDC.Hostname)"", the rest of DCs will be skipped." }
										
									}
									
									else
									{
										Write-Verbose "Other Unknown Error was returned when running Get-ADUser for user ""$User"" from ""$($VerifiedDC.HostName)"""
									}
									
									
								}
								
								else
								{
									
									if ($UserInfo -ne $null -and $ERROR_CATCH_UserInfo -eq $null)
									{
										
										Write-Verbose "Results were returned from when searching for user ""$User"""
										[pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = $UserInfo.SamAccountName
											UserName = $User
											GivenName = $UserInfo.GivenName
											SurName = $UserInfo.SurName
											DisplayName = $UserInfo.DisplayName
											Enabled = $UserInfo.Enabled
											PasswordLastSet = $UserInfo.PasswordLastSet
											LastLogon = $UserInfo.LastLogon
											LastLogonDate = $UserInfo.LastLogonDate
											Mail = $UserInfo.mail
											WhenCreated = $UserInfo.WhenCreated
											WhenChanged = $UserInfo.WhenChanged
											OU = $UserInfo.OU
										}
										
									}
									
									elseif ($UserInfo -eq $null -and $ERROR_CATCH_UserInfo -eq $null)
									{
										Write-Verbose "NO Results were returned when searching for user ""$User"""
										[pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = "N/A - No Results were returned"
											UserName = $User
											GivenName = "N/A - No Results were returned"
											SurName = "N/A - No Results were returned"
											DisplayName = "N/A - No Results were returned"
											Enabled = "N/A - No Results were returned"
											PasswordLastSet = "N/A - No Results were returned"
											LastLogon = "N/A - No Results were returned"
											LastLogonDate = "N/A - No Results were returned"
										}
									}
									
									elseif ($ERROR_CATCH_UserInfo -ne $null)
									{
										Write-Verbose "ERRORs were returned when searching for user ""$User"""
										[pscustomobject]@{
											DC = $VerifiedDC.HostName
											DCIPAddress = $VerifiedDC.IPV4Address
											DCSite = $VerifiedDC.Site
											#UserName = $ERROR_CATCH_UserInfo
											UserName = $User
											GivenName = $ERROR_CATCH_UserInfo
											SurName = $ERROR_CATCH_UserInfo
											DisplayName = $ERROR_CATCH_UserInfo
											Enabled = $ERROR_CATCH_UserInfo
											PasswordLastSet = $ERROR_CATCH_UserInfo
											LastLogon = $ERROR_CATCH_UserInfo
											LastLogonDate = $ERROR_CATCH_UserInfo
											Mail = $ERROR_CATCH_UserInfo
											WhenCreated = $ERROR_CATCH_UserInfo
											WhenChanged = $ERROR_CATCH_UserInfo
											OU = $ERROR_CATCH_UserInfo
										}
										if ($ERROR_CATCH_UserInfo -eq "User was not Found") { Write-Warning "User ""$User"" was not found in ""$($VerifiedDC.Hostname)"", the rest of DCs will be skipped." }
										
									}
									
									else
									{
										Write-Verbose "Other Unknown Error was returned when running Get-ADUser for user ""$User"" from ""$($VerifiedDC.HostName)"""
									}
								}
								
							}
							#}
							
							
						}
						
						
						
						elseif ($VerifiedDC.DCState -eq "Failed")
						{
							Write-Verbose "Creating Failed Object with DC ""$($VerifiedDC.HostName)"" which is not available."
							[pscustomobject]@{
								DC = $VerifiedDC.HostName
								DCIPAddress = $VerifiedDC.IPV4Address
								DCSite = $VerifiedDC.Site
								#UserName = "N/A - DC is not Available"
								UserName = $User
								GivenName = "N/A - DC is not Available"
								SurName = "N/A - DC is not Available"
								DisplayName = "N/A - DC is not Available"
								Enabled = "N/A - DC is not Available"
								PasswordLastSet = "N/A - DC is not Available"
								LastLogon = "N/A - DC is not Available"
								LastLogonDate = "N/A - DC is not Available"
								Mail = "N/A - DC is not Available"
								WhenCreated = "N/A - DC is not Available"
								WhenChanged = "N/A - DC is not Available"
								OU = "N/A - DC is not Available"
								
							}
						}
						
						
						else
						{
							Write-Verbose "Other Unknown DC State on ""$($VerifiedDC.HostName)"" for user ""$User"" "
							Write-Warning "Skipping ""$($VerifiedDC.HostName)"", Run -Verbose"
							
						}
						
					}
					else { Write-Verbose "Skipping check for user ""$User"" in $($VerifiedDC.HostName)" }
				}
				clv ERROR_CATCH_UserInfo -ErrorAction SilentlyContinue
			}
			else
			{
				Write-Verbose "Starting Query against every Unverified DC"
				foreach ($VerifiedDC in $DCList)
				{
					
					if ($ERROR_CATCH_UserInfo -ne "User was not Found")
					{
						Try
						{
							clv Error_UserInfo, ERROR_CATCH_UserInfo -ErrorAction SilentlyContinue
							
							Write-Verbose "Checking on User ""$User"" with DC ""$($VerifiedDC.Hostname)"""
							
							$UserInfo = Get-ADUser -Identity $User -Server $VerifiedDC.HostName `
												   -Properties GivenName, SurName, Name, DisplayName, LastLogon, LastLogonDate, Enabled, LastBadPasswordAttempt, PasswordLastSet, mail, WhenCreated, WhenChanged -ErrorVariable ERROR_UserInfo -ErrorAction Stop | `
							Select-Object GivenName, SurName, Name, DisplayName, Enabled, SamAccountName, @{ N = 'LastLogon'; E = { [DateTime]::FromFileTime($_.LastLogon) } }, `
										  LastLogonDate, lastLogonTimestamp, LastBadPasswordAttempt, PasswordLastSet, @{ n = 'OU'; E = { $_.distinguishedname -replace '^.+?,(CN|OU.+)', '$1' } }, mail, WhenCreated, WhenChanged
							
						}
						
						Catch [exception]
						
						{
							
							Switch -Regex ($_.Exception)
							{
								
								"Cannot find an object with identity: " { $ERROR_CATCH_UserInfo = "User was not Found" }
								Default { $ERROR_CATCH_UserInfo = $ERROR_UserInfo.ErrorRecord.Exception.Message }
								
							}
							
						}
						
						Finally
						{
							if ($ShowMostRecentOnly)
							{
								Write-Verbose "The ""ShowMostRecentOnly"" Parameter was used"
								if ($UserInfo -ne $null -and $ERROR_CATCH_UserInfo -eq $null)
								{
									[array]$ConsolidatedResultsForUser += [pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = $UserInfo.SamAccountName
										UserName = $User
										GivenName = $UserInfo.GivenName
										SurName = $UserInfo.SurName
										DisplayName = $UserInfo.DisplayName
										Enabled = $UserInfo.Enabled
										PasswordLastSet = $UserInfo.PasswordLastSet
										LastLogon = $UserInfo.LastLogon
										LastLogonDate = $UserInfo.LastLogonDate
										Mail = $UserInfo.Mail
										WhenCreated = $UserInfo.WhenCreated
										WhenChanged = $UserInfo.WhenChanged
										OU = $UserInfo.OU
										
									}
								}
								#Need Separate object for empty results ? - Done
								elseif ($UserInfo -eq $null -and $ERROR_CATCH_UserInfo -eq $null)
								{
									[array]$ConsolidatedResultsForUser += [pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = "N/A - No Results were returned"
										UserName = $User
										GivenName = "N/A - No Results were returned"
										SurName = "N/A - No Results were returned"
										DisplayName = "N/A - No Results were returned"
										Enabled = "N/A - No Results were returned"
										PasswordLastSet = "N/A - No Results were returned"
										LastLogon = "N/A - No Results were returned"
										LastLogonDate = "N/A - No Results were returned"
										Mail = "N/A - No Results were returned"
										WhenCreated = "N/A - No Results were returned"
										WhenChanged = "N/A - No Results were returned"
										OU = "N/A - No Results were returned"
									}
								}
								
								elseif ($ERROR_CATCH_UserInfo -ne $null)
								{
									Write-Verbose "ERRORs were returned when searching for user ""$User"""
									[array]$ConsolidatedResultsForUser += [pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = $ERROR_CATCH_UserInfo
										UserName = $User
										GivenName = $ERROR_CATCH_UserInfo
										SurName = $ERROR_CATCH_UserInfo
										DisplayName = $ERROR_CATCH_UserInfo
										Enabled = $ERROR_CATCH_UserInfo
										PasswordLastSet = $ERROR_CATCH_UserInfo
										LastLogon = $ERROR_CATCH_UserInfo
										LastLogonDate = $ERROR_CATCH_UserInfo
										Mail = $ERROR_CATCH_UserInfo
										WhenCreated = $ERROR_CATCH_UserInfo
										WhenChanged = $ERROR_CATCH_UserInfo
										OU = $ERROR_CATCH_UserInfo
										
									}
									if ($ERROR_CATCH_UserInfo -eq "User was not Found") { Write-Warning "User ""$User"" was not found in ""$($VerifiedDC.Hostname)"", the rest of DCs will be skipped." }
									
								}
								
								else
								{
									Write-Verbose "Other Unknown Error was returned when running Get-ADUser for user ""$User"" from ""$($VerifiedDC.HostName)"""
								}
							}
							
							else
							{
								
								if ($UserInfo -ne $null -and $ERROR_CATCH_UserInfo -eq $null)
								{
									[pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = $UserInfo.SamAccountName
										UserName = $User
										GivenName = $UserInfo.GivenName
										SurName = $UserInfo.SurName
										DisplayName = $UserInfo.DisplayName
										Enabled = $UserInfo.Enabled
										PasswordLastSet = $UserInfo.PasswordLastSet
										LastLogon = $UserInfo.LastLogon
										LastLogonDate = $UserInfo.LastLogonDate
										Mail = $UserInfo.Mail
										WhenCreated = $UserInfo.WhenCreated
										WhenChanged = $UserInfo.WhenChanged
										OU = $UserInfo.OU
										
									}
								}
								#Need Separate object for empty results ? - Done
								elseif ($UserInfo -eq $null -and $ERROR_CATCH_UserInfo -eq $null)
								{
									[pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = "N/A - No Results were returned"
										UserName = $User
										GivenName = "N/A - No Results were returned"
										SurName = "N/A - No Results were returned"
										DisplayName = "N/A - No Results were returned"
										Enabled = "N/A - No Results were returned"
										PasswordLastSet = "N/A - No Results were returned"
										LastLogon = "N/A - No Results were returned"
										LastLogonDate = "N/A - No Results were returned"
										Mail = "N/A - No Results were returned"
										WhenCreated = "N/A - No Results were returned"
										WhenChanged = "N/A - No Results were returned"
										OU = "N/A - No Results were returned"
									}
								}
								
								elseif ($ERROR_CATCH_UserInfo -ne $null)
								{
									Write-Verbose "ERRORs were returned when searching for user ""$User"""
									[pscustomobject]@{
										DC = $VerifiedDC.HostName
										DCIPAddress = $VerifiedDC.IPV4Address
										DCSite = $VerifiedDC.Site
										#UserName = $ERROR_CATCH_UserInfo
										UserName = $User
										GivenName = $ERROR_CATCH_UserInfo
										SurName = $ERROR_CATCH_UserInfo
										DisplayName = $ERROR_CATCH_UserInfo
										Enabled = $ERROR_CATCH_UserInfo
										PasswordLastSet = $ERROR_CATCH_UserInfo
										LastLogon = $ERROR_CATCH_UserInfo
										LastLogonDate = $ERROR_CATCH_UserInfo
										Mail = $ERROR_CATCH_UserInfo
										WhenCreated = $ERROR_CATCH_UserInfo
										WhenChanged = $ERROR_CATCH_UserInfo
										OU = $ERROR_CATCH_UserInfo
										
									}
									if ($ERROR_CATCH_UserInfo -eq "User was not Found") { Write-Warning "User ""$User"" was not found in ""$($VerifiedDC.Hostname)"", the rest of DCs will be skipped." }
									
								}
								
								else
								{
									Write-Verbose "Other Unknown Error was returned when running Get-ADUser for user ""$User"" from ""$($VerifiedDC.HostName)"""
								}
								
							}
						}
						
					}
					else { Write-Verbose "Skipping check for user ""$User"" in $($VerifiedDC.HostName)" }
					
				}
				clv ERROR_CATCH_UserInfo -ErrorAction SilentlyContinue
			}
			
			if ($ShowMostRecentOnly)
			{
				Write-Verbose "Selecting the most recent LastLogon Date for user ""$User"""
				$ConsolidatedResultsForUser | Sort-Object -Property LastLogon -Descending | Select-Object -First 1
			}
		}
	}
	End
	{
		Write-Verbose "Starting ""End"""
	}
}