<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.154
	 Created on:   	10/22/2018 11:24 PM
	 Created by:   	Christian Delgado
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>




<#
	.SYNOPSIS
		A brief description of the Copy-GroupMembership function.
	
	.DESCRIPTION
		Function used to copy the membership of one object to another.
	
	.PARAMETER From
		A description of the From parameter.
	
	.PARAMETER To
		A description of the To parameter.
	
	.EXAMPLE
		PS C:\> Copy-GroupMembership -From 'Value1' -To 'Value2'
	
	.NOTES
		Additional information about the function.
#>
function Copy-GroupMembership
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$From,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[array]$To
	)
	
	#TODO: Place script here
	
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
		
		Write-Verbose "Checking if userid entered in ""From"" parameter exists"
		
		Try
		{
			clv RESULT_getaduser, ERROR_getaduser -ErrorAction SilentlyContinue
			
			$RESULT_getaduser = Get-ADUser -Identity $From -ErrorAction Stop -Properties MemberOf
		}
		
		Catch
		
		{
			switch -regex ($_.Exception)
			{
				Default {$ERROR_getaduser = $Error[0].Exception.Message }
			}
		}
		
		Finally
		{
			if     ($RESULT_getaduser -ne $null -and $ERROR_getaduser -eq $null)
			{
				
				Write-Verbose "Results were returned when running ""Get-ADuser"" for user ""$From"""
				
				$OBJECT_result_getaduser = 	[pscustomobject]@{
																UserName = $From
																Results  = $RESULT_getaduser
																Status   = 'OK'
									 						 }
				
			
			}
			
			elseif ($RESULT_getaduser -eq $null -and $ERROR_getaduser -eq $null)
			{
				Write-Verbose "Displaying error message"
				Write-Host "ERROR - ""$ERROR_getaduser""" -ForegroundColor Red
				Write-Verbose "*No Results or Errors were returned when running ""Get-ADUser"" for user ""$From"",
				script will exit now. *"
				
				$OBJECT_result_getaduser = [pscustomobject]@{
																UserName = $From
																Results  = "Error - No Results"
																Status   = "Error - No Results"
															}
				
				
			}
			
			elseif ($ERROR_getaduser -ne $null)
			{
				Write-Verbose "Displaying error message"
				Write-Host "ERROR - ""$ERROR_getaduser""" -ForegroundColor Red
<<<<<<< HEAD
				Write-Verbose "*Errors were returned when running ""Get-ADUser"" for user ""$From"", script will exit now. *"
				
				$OBJECT_result_getaduser = [pscustomobject]@{
																UserName = $From
																Results  = "Error - $ERROR_getaduser"
																Status   = "Error - $ERROR_getaduser"
															}
				
=======
				Write-Verbose "*Errors were returned when running ""Get-ADUser"" for user ""$From"", script will
				exit now. *"
>>>>>>> parent of c7742fb... Corrected variable and reduced Write-Host comments to one line
			}
			
			else
			{
				Write-Verbose "Displaying error message"
				Write-Host "ERROR - ""$ERROR_getaduser""" -ForegroundColor Red
<<<<<<< HEAD
				Write-Verbose "*No conditions were met when running ""Get-ADUser"" for user ""$From"", script will exit now. *"
				
				$OBJECT_result_getaduser = [pscustomobject]@{
																UserName = $From
																Results  = "Error - No conditions were met"
																Status   = "Error - No conditions were met"
															}
				
=======
				Write-Verbose "*No conditions were met when running ""Get-ADUser"" for user ""$From"", script will
				exit now. *"
>>>>>>> parent of c7742fb... Corrected variable and reduced Write-Host comments to one line
			}
			
			
		}
		
		if ($OBJECT_result_getaduser.status -notlike "OK") { $OBJECT_result_getaduser; Break }
	}
	
	
	Process
	{
		
		foreach ($User in $To)
		{
			
			
			
		}
	}
	
	End
	{
		Write-Host "I'm still going!!!" -ForegroundColor Green
		
	}
}
