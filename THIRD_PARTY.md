# 来源与许可

原创应用、移植适配、工具和测试采用 GPL-3.0（见 LICENSE）。第三方代码、字体、图像和原库研究材料分别按以下说明保留权利，不能把一个组件的许可证套给其他组件。

| 组件 | 来源与范围 |
| --- | --- |
| `sdk/` | HelloClyde/bbk-h1-bda-sdk，固定58bb60d2cf9b7783f5bc31ed35d6e28606871ec7。原创通用适配Apache-2.0；各媒体、libc、堆、图像组件许可证见sdk/LICENSE、NOTICE和sdk/sdk/media/THIRD_PARTY.md。 |
| `h1-qq-native/third_party/micro-ecc` | kmackay/micro-ecc，2026-11-22取得的固定源码；BSD-2-Clause，保留PROVENANCE与LICENSE。 |
| `h1-qq-native/third_party/monocypher` | Monocypher，源码原有Loup Vaillant版权及BSD-2-Clause / CC0双许可完整保留；本项目按BSD选项使用。 |
| `third_party/cjson` | Dave Gamble及贡献者，MIT，保留LICENSE和源码版权。 |
| `h1-qq-native/third_party/fusion-pixel-12` | TakWolf/Fusion Pixel 12px Mono zh_Hans，2026.11.10版，SIL OFL-1.1；包含原始BDF、来源指纹及组成字体的LICENSES。 |
| `app/assets/font12` | Fusion Pixel原始12px像素；467个回退字符保留GNU Unifont 16.0.04的原始16px点阵，选择其SIL OFL许可；完整许可随资源保存。 |
| `tests/support` | HelloClyde/BBKH1-QQMusic的MIPS固件边界和帧测试工具，GPL-3.0；本仓库按QQ应用重新接入，模拟账号均为合成数据。 |
| QQ协议参考 | Switch QQ v0.5.75、MiraiGo协议布局及此前研究记录。协议实现为H1原生C适配，未包含这些参考项目的完整代码仓库、实际账号信息或原ARM动态库。 |
| `core/`及测试向量 | 原生组件行为还原与验证资料；固定发行包来源为https://github.com/shuiwen879867/QQ-for-Switch/releases/tag/v0.5.75。原库及还原表的上游授权范围未确认；本仓库不替原权利人授予授权，任何对外分发前需要进一步核实。此次建立的是用户要求的私有开发仓库。 |
| QQ图像与皮肤 | 官方QQ标志参考地址及GPT Image提示/来源指纹保存在assets各manifest和prompt中；机械裁切、缩放、RGB565/ARGB打包。商标与参考素材权利仍属原权利人，图像生成不构成商标授权。 |

仅收录本项目生产源码、必要素材与离线夹具；没有原机固件/NAND、真实用户消息/头像/票据、PC中转账号服务或用于运行ARM库的二进制。原生算法对照的历史结论在验证记录中注明边界，原ARM库不作为构建或CI依赖。
