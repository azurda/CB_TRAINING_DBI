function log_instr(msg) {
  send({
    name: 'message',
    payload: msg,
  });
}

function createHook(func_obj, interceptor_body) {
  if(func_obj == null)
    return;
  Interceptor.attach(func_obj, interceptor_body);
}

var CopyFileA = Module.findExportByName("kernel32.dll", "CopyFileA");
var CopyFileExA = Module.findExportByName("kernel32.dll", "CopyFileExA");
var CopyFileExW = Module.findExportByName("kernel32.dll", "CopyFileExW");
var CopyFileW = Module.findExportByName("kernel32.dll", "CopyFileW");
var CreateFileA = Module.findExportByName("kernel32.dll", "CreateFileA");
var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
var DeleteFileA = Module.findExportByName("kernel32.dll", "DeleteFileA");
var DeleteFileW = Module.findExportByName("kernel32.dll", "DeleteFileW");
var GetFileSize = Module.findExportByName("kernel32.dll", "GetFileSize");
var MoveFileExA = Module.findExportByName("kernel32.dll", "MoveFileExA");
var MoveFileExW = Module.findExportByName("kernel32.dll", "MoveFileExW");
var MoveFileWithProgressA = Module.findExportByName("kernel32.dll", "MoveFileWithProgressA");
var MoveFileWithProgressW = Module.findExportByName("kernel32.dll", "MoveFileWithProgressW");
var ReadFile = Module.findExportByName("kernel32.dll", "ReadFileEx");
var ReadFileEx = Module.findExportByName("kernel32.dll", "ReadFileEx");
var ReplaceFileA = Module.findExportByName("kernel32.dll", "ReplaceFileA");
var ReplaceFileW = Module.findExportByName("kernel32.dll", "ReplaceFileW");
var SetFileTime = Module.findExportByName("kernel32.dll", "SetFileTime");
var WriteFile = Module.findExportByName("kernel32.dll", "WriteFile");
var GetFileAttributesW = Module.findExportByName("kernel32.dll", "GetFileAttributesW");

createHook(CreateFileW, {
  onEnter: function(args) {
    this.lpFileName = args[0];
    this.dwDesiredAccess = args[1];
    this.dwShareMode = args[2];
    this.lpSecurityAttributes = args[3];
    this.dwCreationDisposition = args[4];
    this.dwFlagsAndAttributes = args[5];
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "CreateFileW",
        "lpFileName": Memory.readUtf16String(this.lpFileName),
        "dwDesiredAccess": this.dwDesiredAccess,
        "dwShareMode": this.dwShareMode,
        "lpSecurityAttributes": this.lpSecurityAttributes,
        "dwCreationDisposition": this.dwCreationDisposition,
        "dwFlagsAndAttributes": this.dwFlagsAndAttributes,
        "retval": retval.toString(),
      });
    }
  });

createHook(CreateFileA, {
  onEnter: function(args) {
    this.lpFileName = args[0];
    this.dwDesiredAccess = args[1];
    this.dwShareMode = args[2];
    this.lpSecurityAttributes = args[3];
    this.dwCreationDisposition = args[4];
    this.dwFlagsAndAttributes = args[5];

    // if (this.dwCreationDisposition.toString() == "0x1" || this.dwCreationDisposition.toString() == "0x2") {
    //   log_instr({
    //     "lpFileName": Memory.readAnsiString(this.lpFileName)
    //   });
    //   log_instr({
    //     "lpFileName": Memory.readAnsiString(this.lpFileName),
    //   });

    //   // saveFile(Memory.readAnsiString(args[0]));
    // }
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "CreateFileA",
      "lpFileName": Memory.readAnsiString(this.lpFileName),
      "dwDesiredAccess": this.dwDesiredAccess,
      "dwShareMode": this.dwShareMode,
      "lpSecurityAttributes": this.lpSecurityAttributes,
      "dwCreationDisposition": this.dwCreationDisposition,
      "dwFlagsAndAttributes": this.dwFlagsAndAttributes,
      "retval": retval.toString(),
    });
  }
});



createHook(WriteFile, {
  onEnter: function(args) {
    this.hFile = args[0];
    this.lpBuffer = args[1];
    this.nNumberOfBytesToWrite = args[2];
    this.lpNumberOfBytesWritten = args[3];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "WriteFile",
      "hFile": this.hFile,
      "lpBuffer": Memory.readCString(this.lpBuffer),
      "nNumberOfBytesToWrite": this.nNumberOfBytesToWrite,
      "lpNumberOfBytesWritten": this.lpNumberOfBytesWritten,
      "retval": retval,
    });
  }
});


createHook(ReadFileEx, {
  onEnter: function(args) {
    this.hFile = args[0];
    this.lpBuffer = args[1];
    this.nNumberOfBytesToRead = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "hFile": this.hFile,
      "apicall": "ReadFileEx",
      "lpBuffer": this.lpBuffer,
      "nNumberOfBytesToRead": this.nNumberOfBytesToRead,
      "retval": retval.toString(),
    });
  }
});


createHook(ReadFile, {
  onEnter: function(args) {
    this.hFile = args[0];
    this.lpBuffer = args[1];
    this.nNumberOfBytesToRead = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "hFile": this.hFile,
      "apicall": "ReadFile",
      "lpBuffer": Memory.readCString(this.lpBuffer),
      "nNumberOfBytesToRead": this.nNumberOfBytesToRead,
      "retval": retval.toString(),
    });
  }
});


createHook(MoveFileWithProgressW, {
  onEnter: function(args) {
    this.lpExistingFileName = Memory.readAnsiString(args[0]);
    this.lpNewFileName = Memory.readAnsiString(args[1]);
      // this.lpData = args[3];???????
      this.dwFlags = args[4];
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "MoveFileWithProgressW",
        "lpExistingFileName": this.lpExistingFileName,
        "lpNewFileName": this.lpNewFileName,
        "dwFlags": this.dwFlags,
        "retval": retval,
      });
    }
  });


createHook(MoveFileWithProgressA, {
  onEnter: function(args) {
    this.lpExistingFileName = Memory.readAnsiString(args[0]);
    this.lpNewFileName = Memory.readAnsiString(args[1]);
    this.dwFlags = args[4];
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "MoveFileWithProgressA",
        "lpExistingFileName": this.lpExistingFileName,
        "lpNewFileName": this.lpNewFileName,
        "dwFlags": this.dwFlags,
        "retval": retval,
      });
    }
  });


createHook(ReplaceFileA, {
  onEnter: function(args) {
    this.lpReplacedFileName = Memory.readAnsiString(args[0]);
    this.lpReplacementFileName = Memory.readAnsiString(args[1]);
    this.lpBackupFileName = Memory.readAnsiString(args[2]);
    this.dwReplaceFlags = args[3];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "ReplaceFileA",
      "lpReplacedFileName": Memory.readAnsiString(this.lpReplacedFileName),
      "lpReplacementFileName": Memory.readAnsiString(this.lpReplacementFileName),
      "lpBackupFileName": this.lpBackupFileName,
      "dwReplaceFlags": this.dwReplaceFlags,
      "retval": retval.toString(),
    });
  }
});


createHook(ReplaceFileW, {
  onEnter: function(args) {
      // cstring or utf16?
      this.lpReplacedFileName = args[0];
      this.lpReplacementFileName = args[1];
      this.lpBackupFileName = args[2];
      this.dwReplaceFlags = args[3];
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "ReplaceFileW",
        "lpReplacedFileName": Memory.readUtf16String(this.lpReplacedFileName),
        "lpReplacementFileName": Memory.readUtf16String(this.lpReplacementFileName),
        "lpBackupFileName": this.lpBackupFileName,
        "dwReplaceFlags": this.dwReplaceFlags,
        "retval": retval.toString(),
      });
    }
  });


createHook(MoveFileExA, {
  onEnter: function(args) {
      // afaik movefileex moves a pointer to a c string (from msdn docs)
      // but could be an Ansi given A (not in msdn)
      this.lpExistingFileName = Memory.readAnsiString(args[0]);
      this.lpNewFileName = Memory.readAnsiString(args[1]);
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "MoveFileExA",
        "lpExistingFileName": this.lpExistingFileName,
        "lpNewFileName": this.lpNewFileName,
        "retval": retval.toString(),
      });
    }
  });


createHook(MoveFileExW, {
  onEnter: function(args) {
      // afaik movefileex moves a pointer to a c string (from msdn docs)
      this.lpExistingFileName = Memory.readAnsiString(args[0]);
      this.lpNewFileName = Memory.readAnsiString(args[1]);
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "MoveFileExW",
        "lpExistingFileName": this.lpExistingFileName,
        "lpNewFileName": this.lpNewFileName,
        "retval": retval.toString(),
      });
    }
  });


createHook(CopyFileExW, {
  onEnter: function(args) {
    this.lpExistingFileName = args[0];
    this.lpNewFileName = args[1];
    this.lpData = args[3];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "CopyFileExW",
      "lpExistingFileName": Memory.readUtf16String(this.lpExistingFileName),
      "lpNewFileName": Memory.readUtf16String(this.lpNewFileName),
      "lpData": this.lpData,
      "retval": retval.toString(),
    });
  }
});

createHook(CopyFileExA, {
  onEnter: function(args) {
    this.lpExistingFileName = args[0];
    this.lpNewFileName = args[1];
    this.lpData = args[3];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "CopyFileExA",
      "lpExistingFileName": Memory.readAnsiString(this.lpExistingFileName),
      "lpNewFileName": Memory.readAnsiString(this.lpNewFileName),
      "lpData": this.lpData,
      "retval": retval.toString(),
    });
  }
});


createHook(CopyFileW, {
  onEnter: function(args) {
    this.lpExistingFileName = args[0];
    this.lpNewFileName = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "CopyFileW",
      "lpExistingFileName": Memory.readUtf16String(this.lpExistingFileName),
      "lpNewFileName": Memory.readUtf16String(this.lpNewFileName),
      "retval": retval.toString(),
    });
  }
});


createHook(CopyFileA, {
  onEnter: function(args) {
    this.lpExistingFileName = args[0];
    this.lpNewFileName = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "CopyFileA",
      "lpExistingFileName": Memory.readAnsiString(this.lpExistingFileName),
      "lpNewFileName": Memory.readAnsiString(this.lpNewFileName),
      "retval": retval.toString(),
    });
  }
});

createHook(DeleteFileW, {
  onEnter: function(args) {
    this.lpFileName = args[0];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "DeleteFileW",
      "lpFileName": Memory.readUtf16String(this.lpFileName),
      "retval": retval.toString(),
    });
  }
});

createHook(DeleteFileA, {
  onEnter: function(args) {
    this.lpFileName = args[0];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "DeleteFileA",
      "lpFileName": Memory.readAnsiString(this.lpFileName),
      "retval": retval.toString(),
    });
  }
});

createHook(SetFileTime, {
  onEnter: function(args) {
    log_instr({
      "apicall": "SetFileTime",
      "desc": "Tries to modify filetime by calling kernel32.dll!SetFileTime",
    });
  }
});


createHook(GetFileSize, {
  onEnter: function(args) {
    this.hFile = args[0];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "GetFileSize",
      // "hFile": Memory.readUtf16String(this.hFile),
      "hFile": this.hFile,
      "lpFileSizeHigh": retval.toString(),
    });
  }
});

var RegOpenKeyW = Module.findExportByName("Advapi32.dll", "RegOpenKeyW");
var RegOpenKeyA = Module.findExportByName("Advapi32.dll", "RegOpenKeyA");
var RegOpenKeyExA = Module.findExportByName("advapi32.dll", "RegOpenKeyExA");
var RegOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
var RegCreateKeyA = Module.findExportByName("advapi32.dll", "RegCreateKeyA");
var RegCreateKeyW = Module.findExportByName("advapi32.dll", "RegCreateKeyW");
var RegCreateKeyExW = Module.findExportByName("advapi32.dll", "RegCreateKeyExW");
var RegCreateKeyExA = Module.findExportByName("advapi32.dll", "RegCreateKeyExA");
var RegDeleteKeyA = Module.findExportByName("advapi32.dll", "RegDeleteKeyA");
var RegDeleteKeyExA = Module.findExportByName("advapi32.dll", "RegDeleteKeyExA");
var RegDeleteKeyW = Module.findExportByName("advapi32.dll", "RegDeleteKeyW");
var RegDeleteKeyExW = Module.findExportByName("advapi32.dll", "RegDeleteKeyExW");
var RegEnumKeyExW = Module.findExportByName("advapi32.dll", "RegEnumKeyExW");
var RegEnumValueW = Module.findExportByName("advapi32.dll", "RegEnumValueW");
var RegSetValueExW = Module.findExportByName("advapi32.dll", "RegSetValueExW");
var RegSetValueExA = Module.findExportByName("advapi32.dll", "RegSetValueExA");
var RegQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");


createHook(RegQueryValueExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpValueName = args[1];
    this.lpType = args[3];
    this.lpData = args[4];
    this.lpcbData = args[5];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegQueryValueExW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpValueName": Memory.readUtf16String(this.lpValueName),
      "lpType": this.lpType,
      "lpData": Memory.readUtf16String(this.lpData),
      "lpcbData": this.lpcbData,
      "retval": retval.toString(),
    });
  }
});


createHook(RegSetValueExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpValueName = args[1];
    this.dwType = args[3];
    this.lpData = args[4];
    this.cbData = args[5];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegSetValueExW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpValueName": Memory.readUtf16String(this.lpValueName),
      "dwType": this.dwType,
      "lpData": Memory.readUtf16String(this.lpData),
      "cbData": this.cbData,
      "retval": retval.toString(),
    });
  }
});


createHook(RegSetValueExA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpValueName = args[1];
    this.dwType = args[3];
    this.lpData = args[4];
    this.cbData = args[5];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegSetValueExA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpValueName": Memory.readAnsiString(this.lpValueName),
      "dwType": this.dwType,
      "lpData": Memory.readAnsiString(this.lpData),
      "cbData": this.cbData,
      "retval": retval.toString(),
    });
  }
});


createHook(RegEnumValueW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.dwIndex = args[1];
    this.lpValueName = args[2];
    this.lpReserved = args[4];
    this.lpType = args[5];
    this.lpData = args[6];
    this.lpcbData = args[7];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegEnumValueW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "dwIndex": this.dwIndex,
      "lpValueName": Memory.readUtf16String(this.lpValueName),
      "lpReserved": this.lpReserved,
      "lpType": this.lpType,
      "lpData": Memory.readUtf16String(this.lpData),
      "lpcbData": this.lpcbData,
      "retval": retval.toString(),
    });
  }
});


createHook(RegEnumKeyExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.dwIndex = args[1];
      this.lpName = args[2]; // output dake
      this.lpcName = args[3];
      this.lpReserved = args[4];
    },
    onLeave: function(retval) {
      log_instr({
        "apicall": "RegEnumKeyExW",
        "hKey": resolve_hkey(this.hKey.toString()),
        "dwIndex": this.dwIndex,
        "lpName": Memory.readUtf16String(this.lpName),
        "lpcName": Memory.readUtf16String(this.lpcName),
        "lpReserved": this.lpReserved,
        "retval": retval.toString(),
      });
    }
  });


createHook(RegDeleteKeyA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegDeleteKeyA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "retval": retval.toString(),
    });
  }
});


createHook(RegDeleteKeyExA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegDeleteKeyExA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "retval": retval.toString(),
    });
  }
});

createHook(RegDeleteKeyExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegDeleteKeyExA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "retval": retval.toString(),
    });
  }
});

createHook(RegDeleteKeyW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegDeleteKeyW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "retval": retval.toString(),
    });
  }
});


createHook(RegCreateKeyExA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.lpClass = args[3];
    this.dwOptions = args[4];
    this.samDesired = args[5];
    this.phkResult = args[7];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegCreateKeyExA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "lpClass": this.lpClass,
      "dwOptions": this.dwOptions,
      "samDesired": this.samDesired,
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegCreateKeyExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.lpClass = args[3];
    this.dwOptions = args[4];
    this.samDesired = args[5];
    this.phkResult = args[7];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegCreateKeyExW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "lpClass": this.lpClass,
      "dwOptions": this.dwOptions,
      "samDesired": this.samDesired,
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegCreateKeyA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.phkResult = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegCreateKeyA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegCreateKeyW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.phkResult = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegCreateKeyW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegOpenKeyExA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.ulOptions = args[2];
    this.samDesired = args[3];
    this.phkResult = args[4];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegOpenKeyExA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "ulOptions": this.ulOptions,
      "samDesired": this.samDesired,
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegOpenKeyExW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.ulOptions = args[2];
    this.samDesired = args[3];
    this.phkResult = args[4];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall": "RegOpenKeyExW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "ulOptions": this.ulOptions,
      "samDesired": this.samDesired,
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegOpenKeyW, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.phkResult = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall":"RegOpenKeyW",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readUtf16String(this.lpSubKey),
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});


createHook(RegOpenKeyA, {
  onEnter: function(args) {
    this.hKey = args[0];
    this.lpSubKey = args[1];
    this.phkResult = args[2];
  },
  onLeave: function(retval) {
    log_instr({
      "apicall":"RegOpenKeyA",
      "hKey": resolve_hkey(this.hKey.toString()),
      "lpSubKey": Memory.readAnsiString(this.lpSubKey),
      "phkResult": Memory.readPointer(this.phkResult),
      "retval": retval.toString(),
    });
  }
});

