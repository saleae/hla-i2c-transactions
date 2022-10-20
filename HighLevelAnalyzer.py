# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
            'error': {
                'format': 'Error!'
            },
            "hi2c": {
                'format': 'address: {{data.address}}; data[{{data.count}}]: [ {{data.data}} ]'
            }
        }
        
    
    temp_frame = None

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        pass

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # set our frame to an error frame, which will eventually get over-written as we get data.
        if self.temp_frame is None:
            self.temp_frame = AnalyzerFrame("error", frame.start_time, frame.end_time, {
                "address": "error",
                "data": "",
                "count": 0
            }
            )

        if frame.type == "start" or (frame.type == "address" and self.temp_frame.type == "error"):
            frame_to_flush = None
            if frame.type == "start" and self.temp_frame.type != "error":
                # the previous frame hasn't been flushed yet. Likely a repeated start event.
                frame_to_flush = self.temp_frame
            self.temp_frame = AnalyzerFrame("hi2c", frame.start_time, frame.end_time, {
                    "data": "",
                    "count": 0
                }
            )
            return frame_to_flush

        if frame.type == "address":
            self.temp_frame.end_time = frame.end_time
            address_byte = frame.data["address"][0]
            self.temp_frame.data["address"] = hex(address_byte)

        if frame.type == "data":
            self.temp_frame.end_time = frame.end_time
            data_byte = frame.data["data"][0]
            self.temp_frame.data["count"] += 1
            if len(self.temp_frame.data["data"]) > 0:
                self.temp_frame.data["data"] += ", "
            self.temp_frame.data["data"] += hex(data_byte)

        if frame.type == "stop":
            self.temp_frame.end_time = frame.end_time
            new_frame = self.temp_frame
            self.temp_frame = None
            return new_frame
