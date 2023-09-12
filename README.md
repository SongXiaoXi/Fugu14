# Fugu14 Fusion - Untethered iOS 14 Jailbreak with Rootless Tweak Injection

Fugu14 Fusion is a jailbreak prototype featuring rootless tweak injection and incorporating numerous technical elements from Dopamine (Fugu 15 Max).

The rootless version of the Procursus bootstrap is officially supported on iOS 15 and above. Therefore, the version utilized in this project has been pre-built by me and is unable to install new packages from the official source. Some utilities (such as uicache), which should be compiled for iOS 15, exhibit bugs.
Tweak developers should adjust the minimum iOS version to 14 in the theos makefile to enable proper functionality of rootless tweaks.

**Only tested on iPhone 12 running iOS 14.5.1. Kernel struct offsets may not be accurate on other devices or versions.**

The user interface and the installation process may contain bugs. I have not conducted comprehensive testing as certain steps were initially performed manually before being translated into code.
I recommend thoroughly reviewing the code before proceeding with installation. Your involvement in this project for contributions would be highly appreciated.

### Why does this seemingly flawed project exist despite unc0ver, based on Fugu14, having been available for years?
A [consensus](https://github.com/LinusHenze/Fugu14/pull/242#issuecomment-1153121949) has been reached that certain apps frequently trigger kernel panics on iOS 14 devices jailbroken using unc0ver. This issue occurs more frequently with Fugu14 than with cicuta_virosa.
This project merely demonstrates that unstable unc0ver post-exploitation is the cause behind the kernel panics. Over the past two months, my device has encountered only one random kernel panic, even with extensive use of the apps that typically trigger such panics.

# Credit

- Fugu 14   
- Fugu 15   
- Dopamine