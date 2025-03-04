# Usage
```python final.py --input_dir ./apks --result_dir ./output ```
# Note
./apks -> contains apk files
./output -> will contain both .xml and .data
# Work with RAM
In order to enable RAM storage for faster processing use the below command:
``` sudo mkdir -p /mnt/ramdisk ```
``` sudo mount -t tmpfs -o size=2G tmpfs /mnt/ramdisk ```
