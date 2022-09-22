
import os
import sys
import zipfile

class shellDetector():
    def __init__(self):
        self.shellfeatures={
            "libnqshield.so":u"国信灵通",
            "libvenSec.so":u"启明星辰",
            "libvenustech.so":u"启明星辰",
            "libchaosvmp.so":u"娜迦",
            "libddog.so":u"娜迦",
            "libfdog.so":u"娜迦",
            "libedog.so":u"娜迦企业版",
            "libexec.so":u"爱加密",
            "libexecmain.so":u"爱加密",
            "ijiami.dat":u"爱加密",
            "ijiami.ajm":u"爱加密企业版",
            "libsecexe.so":u"梆梆免费版",
            "libsecmain.so":u"梆梆免费版",
            "libSecShell.so":u"梆梆免费版",
            "libDexHelper.so":u"梆梆企业版",
            "libDexHelper-x86.so":u"梆梆企业版",
            ".appkey.so":u"360",
            "libjiagu_ls.so":u"360",
            "libprotectClass.so":u"360",
            "libjiagu.so":u"360",
            "libjiagu_art.so":u"360",
            "libjiagu_x86.so":u"360",
            "libjiagu_a64.so":u"360",
            "libjiagu_x64.so":u"360",
            "libjgdtc.so":u"360",
            "libjgdtc_x86.so":u"360",
            "libjgdtc_a64.so":u"360",
            "libjgdtc_x64.so":u"360",
            "libjgdtc_art.so":u"360",
            "libegis.so":u"通付盾",
            "libNSaferOnly.so":u"通付盾",
            "libnqshield.so":u"网秦",
            "libbaiduprotect.so":u"百度",
            "libbaiduprotect_x86.so":u"百度",
            "libbaiduprotect_art.so":u"百度",
            "baiduprotect1.jar":u"百度加固",
            "aliprotect.dat":u"阿里聚安全",
            "libsgmain.so":u"阿里聚安全",
            "libfakejni.so":u"阿里聚安全",
            "libzuma.so":u"阿里聚安全",
            "libzumadata.so":u"阿里聚安全",
            "libpreverify1.so":u"阿里聚安全",
            "libdemolishdata.so":u"阿里聚安全",
            "libdemolish.so":u"阿里聚安全",
            "libsgsecuritybody.so":u"阿里聚安全",
            "libmobisec.so":u"阿里聚安全",
            "libtup.so":u"腾讯",
            "libshell.so":u"腾讯",
            "mix.dex":u"腾讯",
            "lib/armeabi/mix.dex":u"腾讯",
            "lib/armeabi/mixz.dex":u"腾讯",
            "liblegudb.so":u"腾讯",
            "libshella":u"腾讯",
            "libshellx":u"腾讯",
            "mixz.dex":u"腾讯",
            "libtosprotection.armeabi.so":u"腾讯御安全",
            "libtosprotection.armeabi-v7a.so":u"腾讯御安全",
            "libtosprotection.x86.so":u"腾讯御安全",
            "libshell-super.2019.so":u"腾讯御安全",
            "libBugly-yaq.so":u"腾讯御安全",
            "libzBugly-yaq.so":u"腾讯御安全",
            "tosversion":u"腾讯御安全",
            "libshellx-super.2019.so":u"腾讯御安全",
            "tosprotection":u"腾讯御安全",
            "00O000ll111l.dex":u"腾讯御安全",
            "000O00ll111l.dex":u"腾讯御安全",
            "0000000lllll.dex":u"腾讯御安全",
            "00000olllll.dex":u"腾讯御安全",
            "0OO00l111l1l":u"腾讯御安全",
            "o0oooOO0ooOo.dat":u"腾讯御安全",
            "t86":u"腾讯御安全",
            "libnesec.so":u"网易易盾",
            "libAPKProtect.so":u"APKProtect",
            "libkwscmm.so":u"几维安全",
            "libkwscr.so":u"几维安全",
            "libkwslinker.so":u"几维安全",
            "libx3g.so":u"顶像科技",
            "libapssec.so":u"盛大",
            "librsprotect.so":u"瑞星",
            "libitsec.so":u"海云安加固",
            "libuusafe.jar.so":u"UU安全",
            "libuusafe.so":u"UU安全",
            "libuusafeempty.so":u"UU安全",
            "libreincp.so":u"珊瑚灵御",
            "libreincp_x86.so":u"珊瑚灵御",
            "jiagu_data.bin":u"apktoolplus",
            "sign.bin":u"apktoolplus",
            "libapktoolplus_jiagu.so":u"apktoolplus",
            "mogosec_classes":u"中国移动",
            "mogosec_data":u"中国移动",
            "mogosec_dexinfo":u"中国移动",
            "mogosec_march":u"中国移动",
            "libcmvmp.so":u"中国移动",
            "libmogosec_dex.so":u"中国移动",
            "libmogosec_sodecrypt.so":u"中国移动",
            "ibmogosecurity.so":u"中国移动",
        }

    def shellDetector(self,apkpath):
        zipfiles=zipfile.ZipFile(apkpath)
        nameList=zipfiles.namelist()

        for fileName in nameList:
            try:
                for shell in self.shellfeatures.keys():
                    if shell in fileName:
                        shellType=self.shellfeatures[shell]
                        print(u"经检测，该apk使用了" + shellType + u"进行加固")
                        return True,shellType
            except:
                print("unknown")
                return False,u"unknown"
        print("未加壳")
        return False,u"未加壳"

if __name__ == '__main__':
    gpus = sys.argv[1]
    sd=shellDetector()
    sd.shellDetector(gpus)[1]
