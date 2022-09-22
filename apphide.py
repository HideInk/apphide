# -*- coding: utf-8 -*-
_author_ = 'Hide'

try:
    import re
    import os
    import sys
    import time
    import hashlib
    import platform
    import subprocess
    from tqdm import tqdm
    from time import sleep
    from colorama import Fore, Back, Style
    from androguard.core.bytecodes.apk import APK
except ImportError as e:
    print("[*] 模块未安装,请确认androguard、openssl是否安装,安装命令:\n\tpip install androguard\n\tpip install pyopenssl\n")
    print("[*] 报错信息:", e)
    sys.exit()

host = platform.system().lower()
# 所需工具
java = "java -jar"
apkTool = "./apkTool/apktool.jar"
apksigner = "./apksigner/apksigner.jar"
debugkey = "./debugkey/debug.jks"
# 反编译Apk路径
outPath = "./outApk"
baksmali = "./baksmali/baksmali.jar"
outsmali = "./outSmali/smali"

if host == "windows":
    print(("""
---------------------------------------------------------------------------------
                      ___  _____ _   __     _ _____  ___
                     / _ \| ___ \ | / /    | | ___ \/ _ \   
                    / /_\ \ |_/ / |/ /_____| | |_/ / /_\ \ 
                    |  _  |  __/| |\ \_____| | __ /|  _  |
                    \_| |_/_|   |_| \_\    |_|_|   \_| |_/
                                                              
---------------------------------------------------------------------------------
    """))
else:
    print(("""%s
---------------------------------------------------------------------------------
                      ___  _____ _   __     _ _____  ___
                     / _ \| ___ \ | / /    | | ___ \/ _ \   
                    / /_\ \ |_/ / |/ /_____| | |_/ / /_\ \ 
                    |  _  |  __/| |\ \_____| | __ /|  _  |
                    \_| |_/_|   |_| \_\    |_|_|   \_| |_/
    %s                                                           
---------------------------------------------------------------------------------
    %s""" % ('\033[91m', '\033[91m', '\033[96m')))


# 反编译Apk
def decompileApk():
    decompile = sys.argv[2]
    backCommand = "%s %s -f d %s -o %s " % (java, apkTool, decompile, outPath)
    os.system(backCommand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("应用反编译操作已完成！")


# 回编译Apk
def backCompilationApk():
    backCompilation = sys.argv[2]
    returnCommand = "%s %s -f b %s" % (java, apkTool, backCompilation)
    os.system(returnCommand)
    oldfile = backCompilation + "/dist/*.apk"

    newTestFile = os.getcwd() + "/../重打包.apk"
    cpCommand = "cp " + oldfile + " " + newTestFile
    os.system(cpCommand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("应用回编译操作已完成！")


# 重签名Apk
def autoGraphApk():
    autoGraph = sys.argv[2]
    appname = os.path.basename(autoGraph).split(".")[0]
    modifyappname = re.sub(appname, appname + "重签名", autoGraph)
    cpCommand = "cp " + autoGraph + " " + modifyappname
    os.system(cpCommand)
    reSignatureCommand = "%s %s sign -ks %s --ks-pass pass:123456 %s" % (java, apksigner, debugkey, modifyappname)
    os.system(reSignatureCommand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("应用重签名操作已完成！")


# 获取apk
def getApkFile():
    packageNameCommand = "adb shell \"dumpsys window | grep mCurrentFocus\""
    getPackageName = subprocess.Popen(packageNameCommand, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, universal_newlines=True)
    packageName = getPackageName.stdout.read().split()[2].split("/")[0]
    getApkPath = "adb shell pm path " + packageName
    getApkPathCommand = subprocess.Popen(getApkPath, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, universal_newlines=True)
    apkPath = getApkPathCommand.stdout.read()[8:]
    pullApkCommand = "adb pull " + apkPath
    os.system(pullApkCommand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("获取应用APK操作已完成！")


# 判断设备当前用户
def judgmentAuthority():
    jurisDictionCommand = "adb shell whoami"
    jurisDictionValue = subprocess.Popen(jurisDictionCommand, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, universal_newlines=True)
    jurisDiction = jurisDictionValue.stdout.read()
    return jurisDiction


# 获取data/data/packagename
def getApkData():
    packageNameCommand = "adb shell \"dumpsys window | grep mCurrentFocus\""
    getPackageName = subprocess.Popen(packageNameCommand, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, universal_newlines=True)
    packageName = getPackageName.stdout.read().split()[2].split("/")[0]
    if judgmentAuthority() == "root\n":
        pullApkDataCommand = "adb pull /data/data/" + packageName
        os.system(pullApkDataCommand)
    else:
        cpApkDataCommand = "adb shell \"su -c cp -r /data/data/" + packageName + " /sdcard 2>/dev/null\""
        os.system(cpApkDataCommand)
        pullApkDataCommand = "adb pull /sdcard/" + packageName
        os.system(pullApkDataCommand)
        deleteApkDataCommand = "adb shell su -c rm -rf /sdcard/" + packageName
        os.system(deleteApkDataCommand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("获取应用Data操作已完成！")


# 查看app信息
def getInfoMation():
    appfile = sys.argv[2]
    comocand = "python3 ./appinfo/appinfo.py %s" % (appfile)
    os.system(comocand)


# 生成hook java脚本模板
def HookTemplateJava():
    classPackageName = sys.argv[2]
    methodName = sys.argv[3]
    hookTemplate = """
Java.perform(function() {
    var clazz = Java.use('""" + classPackageName + """');
    clazz.""" + methodName + """.implementation = function() {

        //

        return clazz.""" + methodName + """.apply(this, arguments);
    }
}); 
"""
    filePath = os.getcwd() + "/"
    makefile(filePath, hookTemplate)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("hook脚本文件创建操作已完成！")


# 生成hook oc脚本模板
def HookTemplateOc():
    classPackageName = sys.argv[2]
    methodVlaue = sys.argv[3]
    datamethod = '"' + '+/- ' + methodVlaue + '"'
    hookTemplate = """
var method = ObjC.classes.""" + classPackageName + """[""" + datamethod + """];
var origImp = method.implementation;
method.implementation = ObjC.implement(method,function (self,selector,a1) {
    
    //var b1 = new Objc.Object(a1);

    return origImp(self,selector,b1);

});
"""
    filePath = os.getcwd() + "/"
    makefile(filePath, hookTemplate)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("hook脚本文件创建操作已完成！")


# 创建脚本文件
def makefile(path, content):
    if os.path.exists(path):
        if os.path.isdir(path):
            f = open('../hook.js', 'w')
            f.write(content)
            f.seek(0)
            f.close()


def run(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmdByte = p.stdout.read()
    ret = ""
    try:
        ret = cmdByte.decode('UTF-8')
    except Exception as e:
        ret = cmdByte.decode('gbk')
    return ret


# 加固技术识别
def dexJiaGu():
    appfile = sys.argv[2]
    comocand = "python3 ./reinforce/dex.py %s" % (appfile)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("应用加固识别操作已完成！")
    os.system(comocand)


# frida_dump脱壳
def FridaDumpDex():
    comocand = "python3 ./dumpdex/Frida.py"
    os.system(comocand)
    for char in tqdm(["a"], ncols=81):
        sleep(0.25)
    print("frida_dump脱壳操作已完成！")

# 查看当前运行Activity
def lookupUi():
    commcad = "adb shell \"dumpsys window | grep mCurrentFocus\""
    os.system(commcad)

# 查找敏感文件路径
def lookupFile():
    gpus = sys.argv[2]
    arrsoValue = []
    for root, dirs, files in os.walk(gpus):
        for file in files:
            if os.path.splitext(file)[1] == '.p12':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.cer':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.crt':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.pfx':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.plist':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.js':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.db':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.txt':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.sqlite':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.lua':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.html':
                arrsoValue.append(os.path.join(root, file))
        for file in files:
            if os.path.splitext(file)[1] == '.php':
                arrsoValue.append(os.path.join(root, file))
    for file in arrsoValue:
        print(file)


# 定义打印格式
def stdio(content):
    if False:  # 控制台乱码修改此处为False
        print(Fore.LIGHTCYAN_EX + Style.BRIGHT + str(content) + Style.RESET_ALL)
    else:
        print(str(content))


if __name__ == '__main__':
    try:
        gpus = sys.argv[1]
        if gpus == "-h":
            stdio(" -h                                      帮助命令")
            stdio(" -v                                      查看版本")
            stdio(" -f apkfile                              反编译Apk")
            stdio(" -b outfile                              回编译Apk")
            stdio(" -c apkfile                              重签名Apk")
            stdio(" -ui                                     查看当前运行Activity")
            stdio(" -info appfile                           查看Apk/Ipa信息")
            stdio(" -file appfile                           查看App沙箱敏感文件[js、plist、db等]路径")
            stdio(" -apk                                    获取设备运行Apk文件")
            stdio(" -data                                   获取设备运行Apk data/data/pakname数据文件")
            stdio(" -dumpfrida                              使用frida对apk进行脱壳,手动运行fridaserver")
            stdio(" -hookjava className methodName          生成Hook Java层模版")
            stdio(" -hookoc className methodName            生成Hook Oc层模版，方法前的加减号无须写")
        elif gpus == "-v":
            stdio("version:                                 2.2.0")
        elif gpus == "-info":
            getInfoMation()
        elif gpus == "-apk":
            getApkFile()
        elif gpus == "-data":
            getApkData()
        elif gpus == "-hookjava":
            HookTemplateJava()
        elif gpus == "-hookoc":
            HookTemplateOc()
        elif gpus == "-dex":
            dexJiaGu()
        elif gpus == "-f":
            decompileApk()
        elif gpus == "-b":
            backCompilationApk()
        elif gpus == "-c":
            autoGraphApk()
        elif gpus == "-dumpfrida":
            FridaDumpDex()
        elif gpus == "-file":
            lookupFile()
        elif gpus == "-ui":
            lookupUi()
        else:
            stdio("zz")
    except Exception as e:
        stdio("输入-h，查看命令")
