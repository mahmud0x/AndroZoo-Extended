# Usage
```python final.py --input_dir ./apks --result_dir ./output ```
# Note
./apks -> contains apk files <br />
./output -> will contain both .xml and .data
# Work with RAM
In order to enable RAM storage for faster processing use the below command:<br />
``` sudo mkdir -p /mnt/ramdisk ``` <br />
``` sudo mount -t tmpfs -o size=2G tmpfs /mnt/ramdisk ```
