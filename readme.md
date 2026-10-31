提取
python extractor.py  gamemodes -o translate.json

替换
python .\replacer.py .\translate.translated.json

开始翻译
run_deepseek_translation.bat

翻译完之后
python .\replacer.py .\translate.translated.json

翻译到一半想测试翻译结果
python replacer.py deepseek_cache_preview.json

