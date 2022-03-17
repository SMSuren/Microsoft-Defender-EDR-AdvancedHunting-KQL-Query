let myhostmachine = "aad-5cg145b00x.next.loc";
let avmodetable = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == 'scid-2010' and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))
| project DeviceId, AVMode;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == 'scid-2011' and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVSigVersion = tostring(avdata[0][0])
| extend AVEngineVersion = tostring(avdata[0][1])
| extend AVSigLastUpdateTime = tostring(avdata[0][2])
| extend AVProductVersion = tostring(avdata[0][3])
| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion, IsCompliant, IsApplicable
| join avmodetable on DeviceId
| join kind=inner ( 
DeviceTvmSecureConfigurationAssessment 
| where ConfigurationId in ('scid-2010','scid-2011','scid-2014','scid-2012','scid-2013','scid-2016','scid-2003', 'scid-90') 
| extend IsAvEnabled=iif(ConfigurationId == 'scid-2010' and IsCompliant==1, 1, 0),  
IsRealtimeProtectionEnabled=iif(ConfigurationId == 'scid-2012' and IsCompliant==1, 1, 0), 
IsAVSignatureLatest=iif(ConfigurationId == 'scid-2011' and IsCompliant==1, 1, 0),  
IsAVReporting=iif(ConfigurationId == 'scid-2014' and IsCompliant==1, 1, 0),  
IsPuaEnabled=iif(ConfigurationId == 'scid-2013' and IsCompliant==1, 1, 0),  
IsCloudProtectionEnabled=iif(ConfigurationId == 'scid-2016' and IsCompliant==1, 1, 0),  
IsTamperProtectionEnabled=iif(ConfigurationId == 'scid-2003' and IsCompliant==1, 1, 0),  
IsEmailScanningEnabled=iif(ConfigurationId == 'scid-90' and IsCompliant==1, 1, 0)  
| summarize DeviceName=any(DeviceName), 
IsAvEnabled=max(IsAvEnabled),  
IsRealtimeProtectionEnabled=max(IsRealtimeProtectionEnabled),  
IsAVSignatureLatest=max(IsAVSignatureLatest),  
IsAVReporting=max(IsAVReporting),  
IsPuaEnabled=max(IsPuaEnabled),  
IsCloudProtectionEnabled=max(IsCloudProtectionEnabled),  
IsTamperProtectionEnabled=max(IsTamperProtectionEnabled), 
IsEmailScanningEnabled = max(IsEmailScanningEnabled) 
by DeviceId, Timestamp, OSPlatform
| join kind=inner (
DeviceNetworkEvents
| summarize arg_max(Timestamp, *) by DeviceId
|project DeviceId,LocalIP
) on DeviceId
| join kind=inner ( 
DeviceInfo 
| where isnotempty(OSBuild)
| where LoggedOnUsers contains 'UserName' 
| extend UserloggedIN=tostring(split(LoggedOnUsers,',')[0])
| summarize arg_max(Timestamp, *) by DeviceId,OnboardingStatus
| project DeviceId,OnboardingStatus, DeviceCategory,MachineGroup,UserloggedIN,PublicIP,AadDeviceId  
) on DeviceId 
| project DeviceId,LocalIP,Timestamp, DeviceName, IsAvEnabled, IsRealtimeProtectionEnabled, IsAVSignatureLatest,IsAVReporting, IsPuaEnabled, IsCloudProtectionEnabled, IsTamperProtectionEnabled, IsEmailScanningEnabled,OSPlatform,OnboardingStatus, DeviceCategory,MachineGroup,UserloggedIN,PublicIP,AadDeviceId 
) on DeviceId
| where DeviceName == myhostmachine
| project  AadDeviceId,DeviceId,DeviceName,LocalIP,PublicIP, Timestamp,OSPlatform,AVMode,AVProductVersion,AVEngineVersion,AVSigVersion,AVSigLastUpdateTime,IsAvEnabled, IsRealtimeProtectionEnabled, IsAVSignatureLatest, IsAVReporting, IsPuaEnabled, IsCloudProtectionEnabled, IsTamperProtectionEnabled, IsEmailScanningEnabled,OnboardingStatus, DeviceCategory,MachineGroup,UserloggedIN