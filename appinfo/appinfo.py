# -*- coding: utf-8 -*-

try:
    import sys
    import os
    import hashlib
    import binascii
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import *
    from colorama import Fore, Back, Style
    import OpenSSL
    import zipfile
    import re
    import plistlib
    from dateutil import parser
except ImportError as e:
    print("[*] 模块未安装,请确认androguard、openssl是否安装,安装命令:\n\tpip install androguard\n\tpip install pyopenssl\n")
    print("[*] 报错信息:", e)
    sys.exit()


# 定义打印格式
def stdio(info, content):
    if False:  # 控制台乱码修改此处为False
        print(info + " " + Fore.LIGHTCYAN_EX + Style.BRIGHT + str(content) + Style.RESET_ALL)
    else:
        print(info + " " + str(content))


class _APK:
    def analyzeApk(self, apkPath):

        apk = APK(apkPath)
        appName = apk.get_app_name()
        packageName = apk.get_package()
        androidVersionName = apk.get_androidversion_name()
        minSdkVersion = apk.get_min_sdk_version()
        maxSdkVersion = apk.get_max_sdk_version()
        # 遍历组件
        application = apk.find_tags_from_xml("AndroidManifest.xml", "application")

        # 基本信息
        stdio("基本信息:", "")
        stdio("\t应用名:", appName)
        stdio("\t包名:", packageName)
        stdio("\t入口:", apk.get_main_activity())
        stdio("\t版本名:", androidVersionName)
        if application != []:
            debuggable = application[0].attrib.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == None:
                debuggable = "false"
            stdio("\t开启调试:", debuggable)
            allowBackup = application[0].attrib.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if allowBackup == None:
                allowBackup = "true"
            stdio("\t允许备份:", allowBackup)
        stdio("\t文件大小:", os.path.getsize(apk.get_filename()))
        stdio("\tSDK版本 minSdkVersion:", minSdkVersion)
        stdio("\tSDK版本 targetSdkVersion:", maxSdkVersion)
        stdio("\tDEX文件数量:", len(list(apk.get_dex_names())))
        stdio("\t使用V1签名:", apk.get_certificates_v1() != [])
        stdio("\t使用V2签名:", apk.get_certificates_v2() != [])
        stdio("\t使用V3签名:", apk.get_certificates_v3() != [])
        stdio("\tpermission数量:", len(apk.get_permissions()))
        stdio("\tactivitie数量:", len(apk.get_activities()))
        stdio("\tservice数量:", len(apk.get_services()))
        stdio("\treceiver数量:", len(apk.get_receivers()))
        stdio("\tprovider数量:", len(apk.get_providers()))
        stdio("\tAPK文件数量:", len(apk.get_files()))

        apkByte = open(apk.get_filename(), "rb").read()
        m = hashlib.md5()
        m.update(apkByte)
        apkMd5 = m.hexdigest()
        stdio("\tAPK文件MD5:", apkMd5)
        m = hashlib.sha1()
        m.update(apkByte)
        apkSha1 = m.hexdigest()
        stdio("\tAPK文件SHA1:", apkSha1)
        m = hashlib.sha256()
        m.update(apkByte)
        apkSha256 = m.hexdigest()
        stdio("\tAPK文件SHA256:", apkSha256)

        # 证书信息
        if apk.is_signed():
            stdio("证书信息:", "")
            try:
                cert = apk.get_certificates_v1()[0]
                certSha1 = binascii.b2a_hex(cert.sha1)  # 指纹sha1
                certSha256 = binascii.b2a_hex(cert.sha256)  # 指纹sha256

                stdio("\t签名算法:", cert.signature_algo)
                stdio("\t哈希算法:", cert.hash_algo)
                stdio("\t证书序列号:", cert.serial_number)
                stdio("\t证书指纹sha1:", str(certSha1).replace("b'", "").replace("'", ""))
                stdio("\t证书指纹sha256:", str(certSha256).replace("b'", "").replace("'", ""))

                # 文件md5
                m = hashlib.md5()
                m.update(apk.get_signature())
                md5Sign = m.hexdigest()
                stdio("\t证书文件MD5:", md5Sign)
                # 文件sha1
                m = hashlib.sha1()
                m.update(apk.get_signature())
                sha1Sign = m.hexdigest()
                stdio("\t证书文件SHA1:", sha1Sign)
                # 文件sha256
                m = hashlib.sha256()
                m.update(apk.get_signature())
                sha256Sign = m.hexdigest()
                stdio("\t证书文件SHA256:", sha256Sign)

                stdio("\t公钥模数:", "")
                count = 80
                publicKeyModulus = str(cert.public_key['public_key'].parsed['modulus'].native)
                rows = int(len(publicKeyModulus) / count)
                for i in range(0, rows):
                    stdio("\t\t", publicKeyModulus[i * count:(i + 1) * count])
                if len(publicKeyModulus) % count > 0:
                    stdio("\t\t", publicKeyModulus[rows * count:])

                stdio("\t公钥指数:", cert.public_key['public_key'].parsed['public_exponent'].native)

                # 发行人信息
                stdio("\t主体信息:", "")
                issuer = cert.issuer.human_friendly.split(",")
                if issuer != []:
                    for certInfo in issuer:
                        stdio("\t\t", certInfo.replace(" ", ""))
            except Exception as e:
                stdio("证书分析错误", e)


class _IPA:
    # IOS权限列表

    def __init__(self):
        self.permissions = ["NSUserTrackingUsageDescription", "NSDownloadsFolderUsageDescription",
                            "NSDocumentsFolderUsageDescription", "NSNetworkVolumesUsageDescription",
                            "NSRemindersUsageDescription", "NSLocationDefaultAccuracyReduced",
                            "NSPhotoLibraryUsageDescription", "NSSystemAdministrationUsageDescription",
                            "NSBluetoothAlwaysUsageDescription", "NSLocationTemporaryUsageDescriptionDictionary",
                            "NSRemovableVolumesUsageDescription", "NSVideoSubscriberAccountUsageDescription",
                            "NSDesktopFolderUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription",
                            "NSLocationWhenInUseUsageDescription", "NSCameraUsageDescription",
                            "NSLocationAlwaysUsageDescription", "NSFileProviderDomainUsageDescription",
                            "NSBluetoothPeripheralUsageDescription", "NSSpeechRecognitionUsageDescription",
                            "NSPhotoLibraryAddUsageDescription", "OSBundleUsageDescription",
                            "NSFileProviderPresenceUsageDescription", "NSHomeKitUsageDescription",
                            "kTCCServiceMediaLibrary", "NSMicrophoneUsageDescription", "NSMotionUsageDescription",
                            "NSAppleMusicUsageDescription", "NSSiriUsageDescription", "NFCReaderUsageDescription",
                            "NSLocationUsageDescription", "NSCalendarsUsageDescription",
                            "NSHealthUpdateUsageDescription", "NSFaceIDUsageDescription",
                            "NSHealthClinicalHealthRecordsShareUsageDescription", "NSAppleEventsUsageDescription",
                            "NSHealthShareUsageDescription", "NSLocalNetworkUsageDescription",
                            "NSSystemExtensionUsageDescription", "NSContactsUsageDescription"]

    # 搜索Frameworks
    def analyzeFrameworks(self, ipaFile):
        frameworks = set()
        for name in ipaFile.namelist():
            if "Payload" in name and "Frameworks" in name:
                try:
                    tripFrameworks = name[name.index("Frameworks") + 11:]
                    tripSlash = tripFrameworks[:tripFrameworks.index("/")]
                    frameworks.add(tripSlash)
                except Exception as e:
                    pass
        if frameworks != set():
            stdio("使用框架:", "")
            for framework in frameworks:
                stdio("\t", framework)

    # 正则匹配字符串
    def getString(self, certInfo, tag, alias):
        try:
            index = certInfo.index(tag)
            if alias != None:
                tag = alias
            reRet = re.findall("<string>(.*?)</string>", certInfo[index:])[0]
            stdio("\t" + tag + ":", reRet)
        except Exception as e:
            pass

    def getBlooen(self, certInfo, tag, alias):
        try:
            index = certInfo.index(tag)
            if alias != None:
                tag = alias
            reRet = re.findall("</key><(.*?)/>", certInfo[index:])[0]
            stdio("\t" + tag + ":", reRet)
        except Exception as e:
            pass

    def getArray(self, certInfo, tag, alias):
        try:
            index = certInfo.index(tag)
            if alias != None:
                tag = alias
            reRet = re.findall("<array>(.*?)</array>", certInfo[index:])[0]
            splitStr = reRet.split("</string>")
            if len(splitStr) == 2:
                stdio("\t" + tag + ":", splitStr[0].replace("<string>", ""))
            else:
                stdio("\t" + tag + ":", "")
                for str in splitStr:
                    if str != "":
                        stdio("\t\t\t", str.replace("<string>", ""))
        except Exception as e:
            pass

    def getDate(self, certInfo, tag, alias):
        try:
            index = certInfo.index(tag)
            if alias != None:
                tag = alias
            reRet = re.findall("<date>(.*?)</date>", certInfo[index:])[0]
            reRet = parser.parse(reRet)
            stdio("\t" + tag + ":", reRet.strftime('%Y-%m-%d %H:%M:%S'))
        except Exception as e:
            pass

    def getInteger(self, certInfo, tag, alias):
        try:
            index = certInfo.index(tag)
            if alias != None:
                tag = alias
            reRet = re.findall("<integer>(.*?)</integer>", certInfo[index:])[0]
            stdio("\t" + tag + ":", reRet)
        except Exception as e:
            pass

    def getPublicKey(self, certInfo, tag):
        try:
            certArr = []
            index = certInfo.index(tag)
            reRet = re.findall("<array>(.*?)</array>", certInfo[index:])[0]
            splitStr = reRet.split("</data>")
            if len(splitStr) == 2:
                certArr.append(splitStr[0].replace("<data>", ""))
            else:
                for str in splitStr:
                    if str != "":
                        certArr.append(str.replace("<data>", ""))
            return certArr
        except Exception as e:
            pass

    # IOS签名证书路径
    def findEmbeddedPath(self, zip_file):
        name_list = zip_file.namelist()
        pattern = re.compile(r'Payload/[^/]*.app/embedded.mobileprovision')
        for path in name_list:
            m = pattern.match(path)
            if m is not None:
                return m.group()

    def analyzeEmbedded(self, ipaFile):

        embeddedPath = self.findEmbeddedPath(ipaFile)
        certInfo = ""
        if embeddedPath == None:
            stdio("证书信息:", "无")
            return

        stdio("证书信息:", "")
        embeddedDatas = ipaFile.open(embeddedPath).readlines()
        for embeddedData in embeddedDatas:
            try:
                certInfo += embeddedData.decode().strip()
            except Exception as e:
                pass

        embeddedByte = ipaFile.read(embeddedPath)
        self.getString(certInfo, "<key>Name</key>", "名称(Name)")
        self.getString(certInfo, "AppIDName", "ID名称(AppIDName)")
        self.getArray(certInfo, "TeamIdentifier", "团队标识(TeamIdentifier)")
        self.getString(certInfo, "com.apple.developer.team-identifier", None)
        self.getArray(certInfo, "ApplicationIdentifierPrefix", "应用标识前缀(ApplicationIdentifierPrefix)")
        self.getString(certInfo, "application-identifier", "应用标识(application-identifier)")
        self.getString(certInfo, "UUID", "唯一ID(UUID)")
        self.getArray(certInfo, "ProvisionedDevices", "分配设备(ProvisionedDevices)")
        self.getDate(certInfo, "CreationDate", "创建时间(CreationDate)")
        self.getDate(certInfo, "ExpirationDate", "过期时间(ExpirationDate)")
        self.getInteger(certInfo, "TimeToLive", "有效时长(TimeToLive)")
        self.getArray(certInfo, "Platform", "适用平台(Platform)")
        self.getBlooen(certInfo, "IsXcodeManaged", "xcode管理(IsXcodeManaged)")
        self.getBlooen(certInfo, "beta-reports-active", "证书是否存活(beta-reports-active)")
        self.getBlooen(certInfo, "com.apple.developer.healthkit", "使用HealthKIt框架(com.apple.developer.healthkit)")
        self.getArray(certInfo, "keychain-access-groups", "keychain共享组(keychain-access-groups)")
        self.getBlooen(certInfo, "get-task-allow", "允许附加调试(get-task-allow)")
        self.getString(certInfo, "aps-environment", "当前环境(aps-environment)")
        self.getArray(certInfo, "com.apple.security.application-groups", "组标识(com.apple.security.application-groups)")
        self.getString(certInfo, "com.apple.developer.associated-domains",
                       "关联域(com.apple.developer.associated-domains)")
        self.getArray(certInfo, "com.apple.developer.applesignin", "苹果登录(com.apple.developer.applesignin)")
        self.getBlooen(certInfo, "com.apple.external-accessory.wireless-configuration",
                       "获取WIFI列表(com.apple.external-accessory.wireless-configuration)")

        cerArr = self.getPublicKey(certInfo, "DeveloperCertificates")
        if cerArr != []:
            for cer in cerArr:
                x509 = """-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----""" % cer.strip()
                cert2Arr = list(cer.strip())
                for index in range(0, len(cert2Arr) + 70, 70):
                    cert2Arr.insert(index, "\n\t\t")
                ret = ''.join(cert2Arr)
                stdio("\tx509证书:", "\n\t\t-----BEGIN CERTIFICATE-----" + ret + "\n\t\t-----END CERTIFICATE-----")
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
                certIssue = cert.get_issuer()
                stdio("\t\t证书版本:", cert.get_version() + 1)
                stdio("\t\t证书序列号:", hex(cert.get_serial_number()) + " (" + str(cert.get_serial_number()) + ")")
                stdio("\t\t证书中使用的签名算法:", cert.get_signature_algorithm().decode("UTF-8"))
                stdio("\t\t证书签名:", cert.digest(cert.get_signature_algorithm().decode()).decode().replace(":", ""))
                stdio("\t\t颁发者:", certIssue.commonName)
                datetime_struct_Before = parser.parse(cert.get_notBefore().decode("UTF-8"))
                datetime_struct_After = parser.parse(cert.get_notAfter().decode("UTF-8"))

                stdio("\t\t有效期:",
                      datetime_struct_Before.strftime('%Y-%m-%d %H:%M:%S') + " 至 " + datetime_struct_After.strftime(
                          '%Y-%m-%d %H:%M:%S'))
                stdio("\t\t证书是否已经过期:", cert.has_expired())
                stdio("\t\t公钥长度", cert.get_pubkey().bits())
                stdio("\t\t公钥:\n",
                      "\t\t\t" + OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode(
                          "utf-8").replace("\n", "\n\t\t\t"))
                stdio("\t\t主体信息:", "")
                infoDict = {"CN": "通用名称", "OU": "机构单元名称", "O": "机构名", "L": "地理位置", "S": "州/省名", "C": "国名"}
                for item in certIssue.get_components():
                    stdio("\t\t\t" + infoDict[item[0].decode("utf-8")] + ":", item[1].decode("utf-8"))
        m = hashlib.md5()
        m.update(embeddedByte)
        embeddedMd5 = m.hexdigest()
        stdio("\t证书文件MD5:", embeddedMd5)
        m = hashlib.sha1()
        m.update(embeddedByte)
        embeddedSha1 = m.hexdigest()
        stdio("\t证书文件SHA1:", embeddedSha1)
        m = hashlib.sha256()
        m.update(embeddedByte)
        embeddedSha256 = m.hexdigest()
        stdio("\t证书文件SHA256:", embeddedSha256)

    # 查找可执行文件在压缩包中的路径 /Payload/name.app/name
    def findExecFilePath(self, zip_file, execFileName):
        name_list = zip_file.namelist()
        for path in name_list:
            if path[:7] == "Payload":
                appName = path.split("/")[1][:-4]
                if len(appName) < 3:  # /Payload 分割后长度小于3需要过滤
                    continue
                execFilePath = "Payload/%s.app/%s" % (appName, appName)
                return execFilePath

    # bangcle混淆（结果不准确）
    def isbangcleObfuscators(self, ipaFile, execFileName):
        execFilePath = self.findExecFilePath(ipaFile, execFileName)
        try:
            execFileDatas = ipaFile.open(execFilePath).readlines()
        except Exception as e:
            return "读取执行文件失败,手动检查"
        execFileStrData = ''
        for execFileData in execFileDatas:
            try:
                nowDecodeStr = execFileData.decode().strip()
                if '2e94317725c3d5f1a4558b7bda33e3cf' in nowDecodeStr or '2e94317725c3d5f1a4558b7bda33e3cf'.upper() in nowDecodeStr:
                    return True
                execFileStrData += nowDecodeStr
            except Exception as e:
                pass

        # readlines安装读取数据，特征字符串可能不再一行,所以将所有字符串拼接做最后的验证
        if '2e94317725c3d5f1a4558b7bda33e3cf' in execFileStrData or '2e94317725c3d5f1a4558b7bda33e3cf'.upper() in execFileStrData:
            return True
        return False

    # Info.plist路径
    def findPlistPath(self, zip_file):
        name_list = zip_file.namelist()
        pattern = re.compile(r'Payload/[^/]*.app/Info.plist')
        for path in name_list:
            m = pattern.match(path)
            if m is not None:
                return m.group()

    def analyzeIPA(self, ipa_path):
        ipaByte = open(ipa_path, "rb").read()
        ipaFile = zipfile.ZipFile(ipa_path)
        plistPath = self.findPlistPath(ipaFile)  # 查找plist文件在压缩包中路径
        plistData = ipaFile.read(plistPath)
        plistRoot = plistlib.loads(plistData)

        # 基本信息
        stdio("基本信息:", "")
        stdio("\t应用名:", plistRoot.get("CFBundleDisplayName"))
        stdio("\t包名:", plistRoot.get("CFBundleIdentifier"))
        stdio("\t发布版本:", plistRoot.get("CFBundleShortVersionString"))
        stdio("\t内部版本:", plistRoot.get("CFBundleVersion"))
        stdio("\t二进制文件:", plistRoot.get("CFBundleExecutable"))
        stdio("\t梆梆混淆:", self.isbangcleObfuscators(ipaFile,plistRoot.get("CFBundleExecutable"))) #不准确
        stdio("\t文件大小:", os.path.getsize(ipa_path))
        stdio("\t最低OS版本:", plistRoot.get("MinimumOSVersion"))
        stdio("\t构建机器版本:", plistRoot.get("BuildMachineOSBuild"))
        stdio("\t所属地区:", plistRoot.get("CFBundleDevelopmentRegion"))
        stdio("\t安装包类型:", plistRoot.get("CFBundlePackageType"))
        stdio("\t支持平台:", plistRoot.get("CFBundleSupportedPlatforms"))
        stdio("\tiTunes共享:", plistRoot.get("UIFileSharingEnabled"))
        stdio("\t支持设备:", str(plistRoot.get("UIDeviceFamily")) + " （1为iPhone和iPod touch设备,2为iPad）")
        stdio("\t内嵌字体:", str(plistRoot.get("UIAppFonts")))
        stdio("\tATS:", str(plistRoot.get("NSAppTransportSecurity")))
        stdio("\t编辑程序:", plistRoot.get("DTCompiler"))
        stdio("\t平台代码:", plistRoot.get("DTPlatformBuild"))
        stdio("\t平台名称:", plistRoot.get("DTPlatformName"))
        stdio("\t平台版本:", plistRoot.get("DTPlatformVersion"))
        stdio("\tSDK构建版本:", plistRoot.get("DTSDKBuild"))
        stdio("\tSDK构建名称:", plistRoot.get("DTSDKName"))
        stdio("\tDTXcode:", plistRoot.get("DTXcode"))
        stdio("\tDTXcodeBuild:", plistRoot.get("DTXcodeBuild"))
        stdio("\tITSAppUsesNonExemptEncryption:", plistRoot.get("ITSAppUsesNonExemptEncryption"))

        m = hashlib.md5()
        m.update(ipaByte)
        ipaMd5 = m.hexdigest()
        stdio("\tIPA文件MD5:", ipaMd5)
        m = hashlib.sha1()
        m.update(ipaByte)
        ipaSha1 = m.hexdigest()
        stdio("\tIPA文件SHA1:", ipaSha1)
        m = hashlib.sha256()
        m.update(ipaByte)
        ipaSha256 = m.hexdigest()
        stdio("\tIPA文件SHA256:", ipaSha256)

        if plistRoot.get("CFBundleIcons") != None and plistRoot.get("CFBundleIcons") != [] and plistRoot.get(
                "CFBundleIcons").get("CFBundlePrimaryIcon") != None and plistRoot.get("CFBundleIcons").get(
                "CFBundlePrimaryIcon").get("CFBundleIconFiles") != None:
            stdio("\t图标:", "")
            if plistRoot.get("CFBundleIcons").get("CFBundlePrimaryIcon").get("CFBundleIconFiles") != []:
                for CFBundleIconFile in plistRoot.get("CFBundleIcons").get("CFBundlePrimaryIcon").get(
                        "CFBundleIconFiles"):
                    stdio("\t\t", CFBundleIconFile)


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 2:
        stdio("ERROR:", "参数输入错误")
        stdio("Example:", "python appinfo.py  xxx.apk/xxx.ipa")
        sys.exit()

    if not os.path.isfile(sys.argv[1]):
        stdio("ERROR:", "文件不存在")
        sys.exit()

    if not zipfile.is_zipfile(sys.argv[1]):
        stdio("ERROR:", "不是有效的apk/ipa文件")
        sys.exit()
    # if sys.argv[1][-4:] != ".ipa" or sys.argv[1][-4:] != ".apk":
    #     stdio("ERROR:","不是IPA文件")
    #     sys.exit()

    if sys.argv[1][-4:] == ".ipa":
        _IPA().analyzeIPA(sys.argv[1])
    elif sys.argv[1][-4:] == ".apk":
        _APK().analyzeApk(sys.argv[1])
    else:
        stdio("ERROR:", "文件后缀非apk/ipa")

    # pip install androguard
    # pip install pyopenssl
