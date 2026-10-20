using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Media;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Windows.Automation;
using Forms = System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("YY Voice Assistant")]
[assembly: System.Reflection.AssemblyVersion("0.1.3.0")]
[assembly: System.Reflection.AssemblyFileVersion("0.1.3.0")]

// YY 9.59/9.60 adapter. Only query/read access to YY; no injection, memory writes,
// keyboard hooks or access to a game's process. Reject unknown binary hashes.
internal sealed class Snapshot
{
    public string Status = "等待 YY";
    public string Generation = "";
    public bool? Muted;
    public int NativeMicFlag=-1;
    public uint Channel;
    public List<ulong> Speakers = new List<ulong>();
    public bool SpeakersReadable;
    public int ProcessId;
    public List<Member> Members = new List<Member>();
    public bool RosterReadable;
}

internal sealed class Member
{
    public ulong Uid;
    public string Name;
    public uint Channel;
}

internal sealed class YYReader : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Region
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public UIntPtr RegionSize;
        public uint State, Protect, Type;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out Region info, UIntPtr length);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    private sealed class ModuleEntry
    {
        public string Name, Path;
        public IntPtr BaseAddress;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool K32EnumProcessModulesEx(IntPtr process,[Out] IntPtr[] modules,uint size,out uint needed,uint filter);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint K32GetModuleFileNameExW(IntPtr process,IntPtr module,StringBuilder path,uint count);
    private static List<ModuleEntry> Modules(int pid)
    {
        // Framework 4 Process.Modules omits this target's 32-bit modules.
        // LIST_MODULES_ALL explicitly includes them with query/read access.
        var modules=new List<ModuleEntry>();
        IntPtr process=OpenProcess(0x410,false,pid);
        if(process==IntPtr.Zero) return modules;
        try {
            var handles=new IntPtr[4096]; uint needed;
            if(!K32EnumProcessModulesEx(process,handles,(uint)(handles.Length*IntPtr.Size),out needed,3) || needed>handles.Length*IntPtr.Size) return modules;
            for(int i=0;i<needed/IntPtr.Size;i++) {
                var path=new StringBuilder(1024);
                if(K32GetModuleFileNameExW(process,handles[i],path,1024)==0) continue;
                modules.Add(new ModuleEntry { Name=System.IO.Path.GetFileName(path.ToString()),Path=path.ToString(),BaseAddress=handles[i] });
            }
        } finally { CloseHandle(process); }
        return modules;
    }
    private IntPtr handle;
    private Process process;
    private uint voiceVtable, proxyVtable, monitorVtable;
    private uint voice, proxy;
    private uint model, modelVtable, userVtable, propertyVtable;
    private List<uint> monitors = new List<uint>();
    private DateTime nextScan = DateTime.MinValue, nextConnect = DateTime.MinValue;
    private string reason = "等待 YY";
    // 9.60 retains the verified QObject vtables and state/layout offsets.
    // Keep an exact per-module allowlist; future builds still require verification.
    private static readonly Dictionary<string,string[]> Hashes = new Dictionary<string,string[]>(StringComparer.OrdinalIgnoreCase) {
        {"bizchannel.dll", new[]{"F252F7D78C863FD705124826791035FA02BA913F77F5481AF814C84AFCEF0098", "EB5264A8D765B3997D7588879468E64AF6569F3FF13224E1CD8F9C8D7DAE374B"}},
        {"channellogic.dll", new[]{"E875AAD549804E803B2845268ACABA61D5C2E3455F688161A16D869318DF4C87", "E8013440039FC9B9E659404E5AF2C6ECE6B6A22DB1DA51DF3ECB0F5CF87F2B77"}},
        {"yycefchannel.dll", new[]{"1B512BF86EC13BEEB2925D46C7E06EFBCF2CA99092835B452501F3D81C02E19B"}},
        {"dwbase.dll", new[]{"504E925B7B7043031E59F8C4AB250AE3BEE6507B30AA2A9A8DEF56D44C953BCF", "4503E6EAB881671E3AD79361EB7B9A1CAF7F9311FCDFD79618A99104EAEFF03E"}}
    };
    public byte[] Read(uint address, int count)
    {
        if (handle == IntPtr.Zero || address < 0x10000 || count < 0 || count > 1048580) return null;
        var bytes = new byte[count]; UIntPtr got;
        return ReadProcessMemory(handle, new IntPtr((long)address), bytes, (UIntPtr)count, out got) && got.ToUInt64() == (ulong)count ? bytes : null;
    }
    private uint U32(uint address) { var b = Read(address,4); return b == null ? 0 : BitConverter.ToUInt32(b,0); }
    private static bool Known(ModuleEntry module)
    {
        string[] expected;
        if (!Hashes.TryGetValue(module.Name,out expected)) return false;
        using (var sha = SHA256.Create()) using(var f = File.OpenRead(module.Path))
            return expected.Contains(BitConverter.ToString(sha.ComputeHash(f)).Replace("-",""));
    }
    private bool Connect()
    {
        if (DateTime.UtcNow < nextConnect) return false;
        nextConnect = DateTime.UtcNow.AddSeconds(3);
        var processes = Process.GetProcessesByName("YY");
        try {
            foreach (var p in processes) {
                var modules = Modules(p.Id);
                var biz = modules.FirstOrDefault(m => String.Equals(m.Name,"bizchannel.dll",StringComparison.OrdinalIgnoreCase));
                var channel = modules.FirstOrDefault(m => String.Equals(m.Name,"channellogic.dll",StringComparison.OrdinalIgnoreCase));
                if (biz == null || channel == null) { reason="等待 YY 语音模块就绪"; continue; }
                if (!Known(biz) || !Known(channel)) { reason = "此 YY 版本需要适配"; continue; }
                handle = OpenProcess(0x410,false,p.Id);
                if (handle == IntPtr.Zero) { reason = "无法读取 YY 状态"; continue; }
                process = Process.GetProcessById(p.Id);
                voiceVtable = checked((uint)biz.BaseAddress.ToInt64() + 399680);
                proxyVtable = checked((uint)biz.BaseAddress.ToInt64() + 363044);
                monitorVtable = checked((uint)channel.BaseAddress.ToInt64() + 897408);
                var cef=modules.FirstOrDefault(m=>String.Equals(m.Name,"yycefchannel.dll",StringComparison.OrdinalIgnoreCase));
                var dw=modules.FirstOrDefault(m=>String.Equals(m.Name,"dwbase.dll",StringComparison.OrdinalIgnoreCase));
                if(cef!=null && dw!=null && Known(cef) && Known(dw)) {
                    modelVtable=(uint)cef.BaseAddress.ToInt64()+2052296;
                    userVtable=(uint)cef.BaseAddress.ToInt64()+0x1f5184;
                    propertyVtable=(uint)dw.BaseAddress.ToInt64()+0x38a6c;
                }
                nextScan = DateTime.MinValue;
                return true;
            }
            if (processes.Length == 0) reason = "等待 YY 启动";
        } catch { reason = "正在等待 YY 就绪"; }
        finally { foreach (var p in processes) p.Dispose(); }
        return false;
    }
    private void FindObjects()
    {
        nextScan = DateTime.UtcNow.AddSeconds(5);
        var voices = new List<uint>(); var foundMonitors = new List<uint>();
        ulong address = 0;
        while (address < 0x100000000UL) {
            Region r;
            if (VirtualQueryEx(handle,new IntPtr((long)address),out r,(UIntPtr)Marshal.SizeOf(typeof(Region))) == UIntPtr.Zero) break;
            ulong start = (ulong)r.BaseAddress.ToInt64(), size = r.RegionSize.ToUInt64();
            if (size == 0 || start + size <= address) break;
            uint protect = r.Protect & 255;
            if (r.State == 0x1000 && r.Type == 0x20000 && (r.Protect & 0x100) == 0 && (protect == 4 || protect == 8 || protect == 0x40 || protect == 0x80)) {
                for (ulong offset=0; offset<size && start+offset<0x100000000UL; offset+=1048576) {
                    int n = (int)Math.Min(1048576UL,size-offset);
                    var data = Read((uint)(start+offset),n);
                    if (data == null) continue;
                    for (int i=0;i+4<=data.Length;i+=4) {
                        if(data[i]!=(byte)voiceVtable && data[i]!=(byte)monitorVtable && data[i]!=(byte)modelVtable) continue;
                        uint v=BitConverter.ToUInt32(data,i), a=(uint)(start+offset+(ulong)i);
                        if (v==voiceVtable) voices.Add(a);
                        if (modelVtable!=0 && v==modelVtable) model=a;
                        if (v==monitorVtable && U32(a+8)==monitorVtable+44 && U32(a+20)!=0) foundMonitors.Add(a);
                    }
                }
            }
            address=start+size;
        }
        var valid = new List<Tuple<uint,uint>>();
        foreach (uint v in voices) {
            // Verified getSoftMute chain: voice+0x76c -> guard+0x3c -> proxy+0x44.
            uint guard=U32(v+0x76c), p=U32(guard+0x3c);
            var flags=Read(p+0x44,2);
            if (U32(p)==proxyVtable && flags!=null && flags[0]<=1 && flags[1]<=1) valid.Add(Tuple.Create(v,p));
        }
        voice=proxy=0;
        if (valid.Count==1) { voice=valid[0].Item1; proxy=valid[0].Item2; nextScan=DateTime.UtcNow.AddSeconds(15); }
        monitors=foundMonitors;
    }
    private bool ReadSpeakers(uint monitor, out uint channel, out List<ulong> users)
    {
        channel=0; users=new List<ulong>();
        if (U32(monitor)!=monitorVtable || U32(monitor+8)!=monitorVtable+44) return false;
        channel=U32(monitor+20);
        uint ptr=U32(monitor+24); var head=Read(ptr,16);
        if (head==null || channel==0) return false;
        int alloc=BitConverter.ToInt32(head,4), begin=BitConverter.ToInt32(head,8), end=BitConverter.ToInt32(head,12);
        if (begin<0 || end<begin || alloc<end || alloc>4096 || end-begin>128) return false;
        // YY's Qt build adds a DWORD before QList slots; begin/end start at +20.
        var slots=Read(ptr+20+(uint)begin*4,(end-begin)*4);
        if (slots==null) return false;
        for (int i=0;i<slots.Length;i+=4) {
            var id=Read(BitConverter.ToUInt32(slots,i),8);
            if (id==null) return false;
            ulong uid=BitConverter.ToUInt64(id,0);
            if (uid==0) return false;
            users.Add(uid);
        }
        var again=Read(ptr,16);
        return again!=null && head.SequenceEqual(again) && U32(monitor+24)==ptr && U32(monitor+20)==channel;
    }
    private bool ReadRoster(uint channel,out List<Member> members)
    {
        members=new List<Member>();
        if(modelVtable==0 || U32(model)!=modelVtable) return false;
        uint hash=U32(model+0x24); var header=Read(hash,28);
        if(header==null) return false;
        int count=BitConverter.ToInt32(header,12),buckets=BitConverter.ToInt32(header,24);
        if(count<0 || count>20000 || buckets<0 || buckets>65536) return false;
        uint array=BitConverter.ToUInt32(header,4);
        var seen=new HashSet<uint>();
        for(int i=0;i<buckets;i++) {
            uint node=U32(array+(uint)i*4);
            while(node!=hash) {
                if(node==0 || !seen.Add(node) || seen.Count>count) return false;
                var data=Read(node,20); if(data==null) return false;
                ulong uid=BitConverter.ToUInt64(data,8); uint item=BitConverter.ToUInt32(data,16);
                if(U32(item)!=userVtable) return false;
                uint prop=U32(item+32);
                if(U32(prop)!=propertyVtable) return false;
                var identity=Read(prop+32,8);
                if(identity==null || BitConverter.ToUInt64(identity,0)!=uid) return false;
                uint sub=PropertyUInt(prop,8);
                string name=PropertyString(prop,1);
                if(sub==channel) {
                    if(String.IsNullOrWhiteSpace(name)) return false;
                    members.Add(new Member {Uid=uid,Name=name,Channel=sub});
                }
                node=BitConverter.ToUInt32(data,0);
            }
        }
        return seen.Count==count && U32(model+0x24)==hash && header.SequenceEqual(Read(hash,28) ?? new byte[0]);
    }
    private int PropertyOffset(uint property,uint key,int type)
    {
        uint schema=U32(property+12),table=U32(schema+84),count=U32(schema+88);
        if(count>512) return -1;
        var data=Read(table,(int)count*8); if(data==null) return -1;
        for(int i=0;i<data.Length;i+=8) if(BitConverter.ToUInt32(data,i)==key && BitConverter.ToUInt16(data,i+6)==type)
            return BitConverter.ToUInt16(data,i+4)/8;
        return -1;
    }
    private uint PropertyUInt(uint property,uint key)
    {
        int offset=PropertyOffset(property,key,3); return offset<0 ? 0 : U32(property+32+(uint)offset);
    }
    private string PropertyString(uint property,uint key)
    {
        int offset=PropertyOffset(property,key,1); if(offset<0) return null;
        uint p=U32(property+32+(uint)offset); if(p==0) return "";
        var bytes=Read(p+6,256); if(bytes==null) return null;
        int end=0; while(end+1<bytes.Length && (bytes[end]!=0 || bytes[end+1]!=0)) end+=2;
        return Encoding.Unicode.GetString(bytes,0,end);
    }
    public Snapshot Poll()
    {
        var s=new Snapshot();
        try {
            if (process!=null && process.HasExited) Dispose();
            if (handle==IntPtr.Zero && !Connect()) { s.Status=reason; return s; }
            s.ProcessId=process.Id;
            if (U32(voice)!=voiceVtable || U32(proxy)!=proxyVtable || U32(U32(voice+0x76c)+0x3c)!=proxy) {
                if(voice!=0 || proxy!=0) nextScan=DateTime.MinValue;
                voice=proxy=0;
                if (DateTime.UtcNow>=nextScan) FindObjects();
            }
            if (voice==0 || proxy==0) { s.Status="等待进入语音频道"; return s; }
            var b=Read(proxy+0x44,1);
            if (b==null || b[0]>1) { s.Status="YY 状态暂不可读"; return s; }
            // Direction verified against the user's YY controls: this field is
            // 1 when the mic is enabled and 0 when disabled, despite the getter's name.
            s.NativeMicFlag=b[0];
            s.Muted=b[0]==0;
            s.Status=s.Muted.Value ? "麦克风已关闭" : "麦克风已开启";
            s.Generation=process.Id+":"+voice+":"+proxy;
            // Only accept one current-channel monitor. An ambiguous state is unknown.
            var readable=new List<Tuple<uint,List<ulong>>>();
            foreach (uint m in monitors) {
                uint channel; List<ulong> users;
                if (ReadSpeakers(m,out channel,out users)) readable.Add(Tuple.Create(channel,users));
            }
            if (readable.Count==1) {
                s.Channel=readable[0].Item1; s.Speakers=readable[0].Item2; s.SpeakersReadable=true;
                s.Generation+=":"+s.Channel;
            }
            List<Member> members;
            if(s.Channel!=0 && ReadRoster(s.Channel,out members)) { s.Members=members; s.RosterReadable=true; }
            if (DateTime.UtcNow>=nextScan) FindObjects();
        } catch { Dispose(); s.Muted=null; s.Status="正在重新连接 YY"; }
        return s;
    }
    public void Dispose()
    {
        if (handle!=IntPtr.Zero) CloseHandle(handle);
        handle=IntPtr.Zero;
        if (process!=null) process.Dispose();
        process=null; voice=proxy=0; monitors.Clear();
        model=modelVtable=userVtable=propertyVtable=0;
    }
}

internal enum MicChange { None, Opened, Closed }

internal sealed class Transition
{
    private string generation="";
    private bool? stable, pending;
    private int count;
    // Two equal polls debounce transitions. Reconnect and unknown states are silent.
    public MicChange Observe(Snapshot s)
    {
        if (!s.Muted.HasValue || s.Generation!=generation) {
            generation=s.Generation; stable=null; pending=null; count=0;
            if (!s.Muted.HasValue) return MicChange.None;
        }
        if (pending!=s.Muted) { pending=s.Muted; count=1; return MicChange.None; }
        if (++count<2 || stable==s.Muted) return MicChange.None;
        MicChange change=!stable.HasValue ? MicChange.None : s.Muted.Value ? MicChange.Closed : MicChange.Opened;
        stable=s.Muted; return change;
    }
}

internal sealed class Preferences
{
    public double X=30, Y=160;
    public bool Locked, Hidden, Sound=true;
    public double Opacity=0.92;
    public string DockSide="";
    public int MaxMembers=6;
    public bool AutoDock=true, PrioritizeSpeakers=true;
    public bool AutoUpdate=true;
    public string OpenSoundFile="", CloseSoundFile="", OpenSoundName="", CloseSoundName="";
    public Dictionary<string,string> Names=new Dictionary<string,string>();
}

internal sealed class MemberSelection
{
    public List<Member> Members;
    public int HiddenCount, HiddenSpeakingCount;
}

internal static class MemberDisplay
{
    public static MemberSelection Select(Snapshot snapshot,int limit,bool prioritize=true)
    {
        var active=new HashSet<ulong>(snapshot.SpeakersReadable ? snapshot.Speakers : new List<ulong>());
        bool overflow=limit>0 && snapshot.Members.Count>limit;
        // Stable ordering within each group avoids reshuffling people who are quiet.
        var members=(overflow && prioritize ? snapshot.Members.OrderByDescending(m=>active.Contains(m.Uid)).ToList() : snapshot.Members.ToList());
        var visible=overflow ? members.Take(limit).ToList() : members;
        var visibleIds=new HashSet<ulong>(visible.Select(m=>m.Uid));
        return new MemberSelection { Members=visible,HiddenCount=snapshot.Members.Count-visible.Count,
            HiddenSpeakingCount=snapshot.Members.Count(m=>active.Contains(m.Uid) && !visibleIds.Contains(m.Uid)) };
    }
    public static bool SelfTest()
    {
        var snapshot=new Snapshot { SpeakersReadable=true,Members=Enumerable.Range(1,8).Select(i=>new Member { Uid=(ulong)i,Name="成员"+i }).ToList() };
        Func<MemberSelection,ulong[],bool> ids=(selection,expected)=>selection.Members.Select(m=>m.Uid).SequenceEqual(expected);
        var first=Select(snapshot,3);
        bool ok=ids(first,new ulong[] {1,2,3}) && first.HiddenCount==5;
        snapshot.Speakers.Add(8);
        ok=ok && ids(Select(snapshot,3),new ulong[] {8,1,2});
        ok=ok && ids(Select(snapshot,3,false),new ulong[] {1,2,3});
        snapshot.Speakers.Add(7);
        ok=ok && ids(Select(snapshot,3),new ulong[] {7,8,1});
        snapshot.Speakers.Clear();
        ok=ok && ids(Select(snapshot,3),new ulong[] {1,2,3});
        snapshot.Speakers.AddRange(new ulong[] {5,6,7,8});
        var crowded=Select(snapshot,3);
        ok=ok && ids(crowded,new ulong[] {5,6,7}) && crowded.HiddenSpeakingCount==1 && crowded.HiddenCount==5;
        ok=ok && ids(Select(snapshot,8),Enumerable.Range(1,8).Select(i=>(ulong)i).ToArray()) && Select(snapshot,0).HiddenCount==0;
        snapshot.SpeakersReadable=false;
        ok=ok && ids(Select(snapshot,3),new ulong[] {1,2,3});
        snapshot.Members.Clear();
        return ok && Select(snapshot,3).Members.Count==0 && Select(snapshot,3).HiddenCount==0;
    }
}

internal sealed class Overlay : Window
{
    public event Action SettingsRequested;
    private StackPanel list;
    private ScrollViewer memberScroll;
    private TextBlock state, foot, more;
    private Canvas mic;
    private readonly Preferences prefs;
    private Snapshot latest=new Snapshot();
    private bool compact, dragging, arranging, waitForLeave;
    private Rect? dockArea;
    private readonly DispatcherTimer fold=new DispatcherTimer { Interval=TimeSpan.FromMilliseconds(350) };
    private string rendered="";
    [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h,int i);
    [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr h,int i,int value);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h,IntPtr after,int x,int y,int w,int height,uint flags);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformationW(IntPtr obj,int index,StringBuilder value,uint size,out uint needed);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    private static string ObjectName(IntPtr handle)
    {
        var value=new StringBuilder(256);uint needed;
        return GetUserObjectInformationW(handle,2,value,512,out needed) ? value.ToString() : "unavailable";
    }
    public object VisibilityReport()
    {
        return new { ProcessId=Process.GetCurrentProcess().Id,Desktop=ObjectName(GetThreadDesktop(GetCurrentThreadId())),
            WindowStation=ObjectName(GetProcessWindowStation()),Visible=IsVisible,
            NativeVisible=IsWindowVisible(new WindowInteropHelper(this).Handle),State=WindowState.ToString(),
            X=Left,Y=Top,Width=ActualWidth,Height=ActualHeight,Hidden=prefs.Hidden,DockSide=prefs.DockSide,Compact=compact,MaxMembers=prefs.MaxMembers };
    }
    private static SolidColorBrush Brush(string color) { return (SolidColorBrush)new BrushConverter().ConvertFromString(color); }
    private static TextBlock Text(string value, double size,string color) { return new TextBlock { Text=value,FontSize=size,Foreground=Brush(color),VerticalAlignment=VerticalAlignment.Center }; }
    public Overlay(Preferences preferences)
    {
        prefs=preferences;
        Title="YY 语音悬浮窗"; Width=232; SizeToContent=SizeToContent.Height;
        WindowStyle=WindowStyle.None; ResizeMode=ResizeMode.NoResize; AllowsTransparency=true;
        Background=System.Windows.Media.Brushes.Transparent; ShowInTaskbar=false; ShowActivated=false; Topmost=true;
        FontFamily=new FontFamily("Microsoft YaHei UI"); Opacity=prefs.Opacity;
        Left=prefs.X; Top=prefs.Y;
        if(!prefs.AutoDock || (prefs.DockSide!="Left" && prefs.DockSide!="Right")) prefs.DockSide="";
        compact=prefs.DockSide!="";
        BuildContent();
        SourceInitialized+=delegate { ApplyLock(); };
        Loaded+=delegate { if(compact) Anchor(); };
        SizeChanged+=delegate { if(!dragging && prefs.DockSide!="") Anchor(); };
        fold.Tick+=delegate { fold.Stop(); if(!dragging && !IsMouseOver && prefs.DockSide!="") SetCompact(true); };
        MouseEnter+=delegate { fold.Stop(); if(!dragging && !waitForLeave && prefs.DockSide!="" && !prefs.Locked) SetCompact(false); };
        MouseLeave+=delegate { waitForLeave=false; if(!dragging && prefs.DockSide!="") { fold.Stop(); fold.Start(); } };
        MouseLeftButtonDown+=delegate {
            if(prefs.Locked) return;
            fold.Stop(); dragging=true;
            try { DragMove(); }
            catch(InvalidOperationException) {}
            finally { dragging=false; DockAfterDrag(); SavePosition(); }
        };
        LocationChanged+=delegate { if(IsLoaded && !arranging && prefs.DockSide=="") SavePosition(); };
    }
    private void BuildContent()
    {
        Width=compact ? 52 : 232;
        list=new StackPanel(); state=new TextBlock(); foot=new TextBlock();
        var stack=new StackPanel();
        if(!compact) {
        var header=new DockPanel { Margin=new Thickness(15,10,14,5) };
        var brand=Text("YY  /  语音",10,"#A9ACB8"); header.Children.Add(brand);
        var dots=SettingsWindow.MakeButton("···"); dots.Width=30; dots.Height=22; dots.Padding=new Thickness(0); dots.Focusable=false; dots.ToolTip="设置";
        dots.Click+=delegate { if(SettingsRequested!=null) SettingsRequested(); };
        DockPanel.SetDock(dots,Dock.Right); header.Children.Insert(0,dots);
        stack.Children.Add(header);
        }
        mic=new Canvas { Width=24,Height=24,HorizontalAlignment=HorizontalAlignment.Center,ToolTip=latest.Status };
        var statusRow=new DockPanel { Margin=compact ? new Thickness(0,10,0,12) : new Thickness(13,3,12,10),LastChildFill=true };
        statusRow.Children.Add(mic);
        if(!compact) { state.FontSize=10; state.Margin=new Thickness(8,0,0,0); state.VerticalAlignment=VerticalAlignment.Center; statusRow.Children.Add(state); }
        stack.Children.Add(statusRow);
        memberScroll=new ScrollViewer { Content=list,MaxHeight=440,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled };
        stack.Children.Add(memberScroll);
        more=Text("",compact ? 22 : 11,"#9296A4"); more.Visibility=Visibility.Collapsed;
        more.HorizontalAlignment=compact ? HorizontalAlignment.Center : HorizontalAlignment.Left;
        more.Margin=compact ? new Thickness(0,0,0,8) : new Thickness(15,0,12,10); stack.Children.Add(more);
        if(!compact) { foot.FontSize=9; foot.Foreground=Brush("#9296A4"); foot.Margin=new Thickness(15,0,12,11); stack.Children.Add(foot); }
        Content=new Border { Background=Brush("#EB20222B"),CornerRadius=new CornerRadius(13),BorderBrush=Brush("#454854"),BorderThickness=new Thickness(1),Child=stack };
        rendered=""; Update(latest);
    }
    private Rect WorkArea()
    {
        var source=PresentationSource.FromVisual(this);
        var scale=source!=null && source.CompositionTarget!=null ? source.CompositionTarget.TransformToDevice : Matrix.Identity;
        var screen=Forms.Screen.FromPoint(new System.Drawing.Point((int)((Left+Width/2)*scale.M11),(int)((Top+20)*scale.M22))).WorkingArea;
        return new Rect(screen.Left/scale.M11,screen.Top/scale.M22,screen.Width/scale.M11,screen.Height/scale.M22);
    }
    private void Anchor()
    {
        if(arranging || prefs.DockSide=="") return;
        arranging=true;
        try { var area=dockArea ?? WorkArea(); dockArea=area; Left=prefs.DockSide=="Left" ? area.Left : area.Right-Width; Top=Math.Max(area.Top,Math.Min(Top,area.Bottom-Math.Max(32,ActualHeight))); }
        finally { arranging=false; }
    }
    private void SetCompact(bool value)
    {
        if(compact==value) return;
        if(prefs.DockSide!="" && !dockArea.HasValue) dockArea=WorkArea();
        compact=value; BuildContent(); Anchor();
    }
    private void DockAfterDrag()
    {
        var area=WorkArea();
        prefs.DockSide=!prefs.AutoDock ? "" : Left<=area.Left+24 ? "Left" : Left+Width>=area.Right-24 ? "Right" : "";
        dockArea=prefs.DockSide=="" ? (Rect?)null : area;
        waitForLeave=prefs.DockSide!="" && IsMouseOver;
        SetCompact(prefs.DockSide!=""); Anchor();
    }
    public void SavePosition() {
        var area=dockArea ?? WorkArea();
        prefs.X=prefs.DockSide=="Right" ? area.Right-52 : Left; prefs.Y=Top;
    }
    public void ApplyLock()
    {
        var h=new WindowInteropHelper(this).Handle;
        if (h==IntPtr.Zero) return;
        int ex=GetWindowLong(h,-20)|0x08000000|0x80;
        if(prefs.Locked) ex|=0x20; else ex&=~0x20;
        SetWindowLong(h,-20,ex);
    }
    public void ResetPosition()
    {
        prefs.DockSide=""; dockArea=null; waitForLeave=false; fold.Stop(); SetCompact(false);
        var screen=Forms.Screen.PrimaryScreen.WorkingArea;
        var source=PresentationSource.FromVisual(this);
        var scale=source!=null && source.CompositionTarget!=null ? source.CompositionTarget.TransformToDevice : Matrix.Identity;
        Left=(screen.Left+30)/scale.M11; Top=(screen.Top+160)/scale.M22;
        SavePosition();
    }
    public void Raise()
    {
        if(!IsVisible) return;
        if(WindowState==WindowState.Minimized) WindowState=WindowState.Normal;
        var source=PresentationSource.FromVisual(this);
        var scale=source!=null && source.CompositionTarget!=null ? source.CompositionTarget.TransformToDevice : Matrix.Identity;
        var rect=new System.Drawing.Rectangle((int)(Left*scale.M11),(int)(Top*scale.M22),
            Math.Max(1,(int)(ActualWidth*scale.M11)),Math.Max(1,(int)(ActualHeight*scale.M22)));
        if(!Forms.Screen.AllScreens.Any(s=> {
            var visible=System.Drawing.Rectangle.Intersect(s.WorkingArea,rect);
            return visible.Width>=(compact ? 24 : 80) && visible.Height>=32;
        })) ResetPosition();
        SetWindowPos(new WindowInteropHelper(this).Handle,new IntPtr(-1),0,0,0,0,0x53);
    }
    public void RefreshMembers() { rendered=""; Update(latest); }
    public void ApplyPreferences()
    {
        Opacity=prefs.Opacity; ApplyLock();
        if(!prefs.AutoDock && prefs.DockSide!="") {
            var area=dockArea ?? WorkArea(); prefs.DockSide=""; dockArea=null; waitForLeave=false; fold.Stop(); SetCompact(false);
            Left=Math.Max(area.Left,Math.Min(Left,area.Right-Width)); SavePosition();
        }
        RefreshMembers();
        if(prefs.Hidden) Hide(); else { Show(); Raise(); }
    }
    public void Update(Snapshot s)
    {
        latest=s;
        string signature=prefs.MaxMembers+":"+s.Status+":"+s.Muted+":"+s.SpeakersReadable+":"+s.RosterReadable+":"+s.Channel+":"+String.Join(",",s.Speakers)+":"+String.Join("|",s.Members.Select(m=>m.Uid+":"+m.Name));
        if(signature==rendered) return;
        rendered=signature; state.Text=s.Status;
        string micColor=!s.Muted.HasValue ? "#A9ACB8" : s.Muted.Value ? "#E8A2AD" : "#8BE1B2";
        mic.Children.Clear(); mic.ToolTip=s.Status;
        mic.Children.Add(new System.Windows.Shapes.Path { Data=Geometry.Parse("M 9,10 L 9,5 C 9,1 15,1 15,5 L 15,10 C 15,14 9,14 9,10 M 5,9 L 5,10 C 5,19 19,19 19,10 L 19,9 M 12,17 L 12,22 M 8,22 L 16,22"),Stroke=Brush(micColor),StrokeThickness=1.8,StrokeStartLineCap=PenLineCap.Round,StrokeEndLineCap=PenLineCap.Round });
        if(s.Muted==true) {
            mic.Children.Add(new Line { X1=3,Y1=3,X2=21,Y2=21,Stroke=Brush("#20222B"),StrokeThickness=5 });
            mic.Children.Add(new Line { X1=3,Y1=3,X2=21,Y2=21,Stroke=Brush(micColor),StrokeThickness=2,StrokeStartLineCap=PenLineCap.Round,StrokeEndLineCap=PenLineCap.Round });
        }
        mic.Opacity=s.Muted.HasValue ? 1 : .55;
        state.Foreground=Brush(!s.Muted.HasValue ? "#A9ACB8" : s.Muted.Value ? "#E8A2AD" : "#8BE1B2");
        list.Children.Clear();
        more.Visibility=Visibility.Collapsed;
        var selection=MemberDisplay.Select(s,prefs.MaxMembers,prefs.PrioritizeSpeakers);
        foreach(Member member in selection.Members) {
            string name=member.Name;
            bool speaking=s.SpeakersReadable && s.Speakers.Contains(member.Uid);
            var row=new DockPanel { Margin=compact ? new Thickness(0,0,0,10) : new Thickness(14,0,13,9),HorizontalAlignment=compact ? HorizontalAlignment.Center : HorizontalAlignment.Stretch };
            var circle=new Border { Width=compact ? 32 : 28,Height=compact ? 32 : 28,CornerRadius=new CornerRadius(16),Background=Brush(speaking ? "#343F3D" : "#383B49"),BorderBrush=Brush(speaking ? "#7BE2AA" : "#626675"),BorderThickness=new Thickness(2),Margin=compact ? new Thickness(0) : new Thickness(0,0,11,0) };
            var initial=Text(String.IsNullOrEmpty(name) ? "?" : System.Globalization.StringInfo.GetNextTextElement(name),11,"#DAF7E4"); initial.HorizontalAlignment=HorizontalAlignment.Center; circle.Child=initial;
            row.Children.Add(circle);
            if(!compact) {
            var dot=new Ellipse {Width=7,Height=7,Fill=Brush(speaking ? "#7BE2AA" : "#737887"),VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(8,0,1,0)};
            DockPanel.SetDock(dot,Dock.Right); row.Children.Add(dot);
            var label=Text(name,12,"#EDF0F7"); label.TextTrimming=TextTrimming.CharacterEllipsis; row.Children.Add(label);
            }
            list.Children.Add(row);
        }
        if(selection.HiddenCount>0) {
            string hint="另有 "+selection.HiddenCount+" 人未显示"+(prefs.PrioritizeSpeakers ? " · 说话时优先显示" : "");
            if(selection.HiddenSpeakingCount>0) hint+="\n其中 "+selection.HiddenSpeakingCount+" 人正在说话，可调高显示人数上限";
            more.Text=compact ? "…" : "…  另有 "+selection.HiddenCount+" 人";
            more.Foreground=Brush(selection.HiddenSpeakingCount>0 ? "#7BE2AA" : "#9296A4"); more.ToolTip=hint;
            more.Visibility=Visibility.Visible; memberScroll.ScrollToTop();
        }
        foot.Text=!s.RosterReadable ? "正在读取频道成员" : s.Members.Count+" 位成员"+(!s.SpeakersReadable ? " · 发言状态暂不可读" : selection.HiddenCount>0 && prefs.PrioritizeSpeakers ? " · 说话时优先显示" : "");
    }
}

internal sealed class AudioCue : IDisposable
{
    private SoundPlayer wave;
    private MediaPlayer media;
    private bool failed;
    public static AudioCue Default(string path)
    {
        var cue=new AudioCue { wave=new SoundPlayer(path) }; cue.wave.Load(); return cue;
    }
    public static async Task<AudioCue> LoadAsync(string path)
    {
        var cue=new AudioCue { media=new MediaPlayer() };
        var player=cue.media;
        var opened=new TaskCompletionSource<bool>();
        EventHandler success=delegate {
            if(!player.HasAudio || !player.NaturalDuration.HasTimeSpan || player.NaturalDuration.TimeSpan<=TimeSpan.Zero)
                opened.TrySetException(new InvalidOperationException("文件中没有可播放的声音。"));
            else opened.TrySetResult(true);
        };
        EventHandler<ExceptionEventArgs> failure=delegate(object sender,ExceptionEventArgs args) { opened.TrySetException(new InvalidOperationException("无法读取音频，请选择有效的 WAV 或 MP3 文件。",args.ErrorException)); };
        cue.media.MediaOpened+=success; cue.media.MediaFailed+=failure;
        try {
            cue.media.Open(new Uri(System.IO.Path.GetFullPath(path)));
            if(await Task.WhenAny(opened.Task,Task.Delay(10000))!=opened.Task) throw new TimeoutException("音频加载超时，请换一个文件。 ");
            await opened.Task;
            cue.media.MediaEnded+=delegate { if(cue.media!=null) cue.media.Stop(); };
            cue.media.MediaFailed+=delegate { cue.failed=true; };
            return cue;
        } catch { cue.Dispose(); throw; }
        finally { player.MediaOpened-=success; player.MediaFailed-=failure; }
    }
    public void Play()
    {
        if(wave!=null) wave.Play();
        else { if(failed) throw new InvalidOperationException("音频播放失败，已恢复使用默认声音。"); media.Position=TimeSpan.Zero; media.Play(); }
    }
    public void Stop() { if(wave!=null) wave.Stop(); else if(media!=null) media.Stop(); }
    public void Dispose() { if(wave!=null) { wave.Stop(); wave.Dispose(); wave=null; } if(media!=null) { media.Close(); media=null; } }
}

internal sealed class AudioBank : IDisposable
{
    private readonly string root, managed;
    private readonly Preferences prefs;
    private readonly Action save;
    private readonly AudioCue[] defaults=new AudioCue[2], custom=new AudioCue[2];
    private readonly string[] errors=new string[2];
    private readonly TaskCompletionSource<bool> ready=new TaskCompletionSource<bool>();
    private bool initializing, disposed;
    public AudioBank(string directory,Preferences preferences,Action saveSettings)
    {
        root=System.IO.Path.GetFullPath(directory); managed=System.IO.Path.Combine(root,"自定义音效"); prefs=preferences; save=saveSettings;
        defaults[0]=AudioCue.Default(System.IO.Path.Combine(root,"开麦.wav")); defaults[1]=AudioCue.Default(System.IO.Path.Combine(root,"关麦.wav"));
    }
    private string SavedFile(bool open) { return open ? prefs.OpenSoundFile : prefs.CloseSoundFile; }
    private void SetFile(bool open,string path,string name) { if(open) { prefs.OpenSoundFile=path; prefs.OpenSoundName=name; } else { prefs.CloseSoundFile=path; prefs.CloseSoundName=name; } }
    private string Resolve(string relative)
    {
        var path=System.IO.Path.GetFullPath(System.IO.Path.Combine(root,relative));
        if(!path.StartsWith(managed+System.IO.Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("自定义音效路径无效，请重新选择音频。");
        return path;
    }
    private void DeleteOld(string relative)
    {
        if(String.IsNullOrEmpty(relative) || relative==prefs.OpenSoundFile || relative==prefs.CloseSoundFile) return;
        try { File.Delete(Resolve(relative)); } catch {}
    }
    public async Task InitializeAsync()
    {
        if(initializing) { await ready.Task; return; } initializing=true;
        try {
            for(int i=0;i<2;i++) {
                string path=SavedFile(i==0); if(String.IsNullOrEmpty(path)) continue;
                try { var cue=await AudioCue.LoadAsync(Resolve(path)); if(disposed) cue.Dispose(); else custom[i]=cue; }
                catch(Exception ex) { errors[i]=ex.Message; }
            }
        } finally { ready.TrySetResult(true); }
    }
    public string Name(bool open)
    {
        int index=open ? 0 : 1; string file=SavedFile(open);
        if(String.IsNullOrEmpty(file)) return open ? "默认 · 上行提示音" : "默认 · 下行提示音";
        string name=open ? prefs.OpenSoundName : prefs.CloseSoundName;
        if(String.IsNullOrEmpty(name)) name=System.IO.Path.GetFileName(file);
        return name+(errors[index]!=null ? "（不可用，暂用默认）" : custom[index]==null ? "（加载中）" : "");
    }
    public void Play(bool open)
    {
        int index=open ? 0 : 1;
        foreach(var cue in defaults.Concat(custom)) if(cue!=null) cue.Stop();
        try { (custom[index] ?? defaults[index]).Play(); }
        catch(Exception ex) { errors[index]=ex.Message; try { defaults[index].Play(); } catch {} }
    }
    public async Task ImportAsync(bool open,string source)
    {
        await ready.Task; if(disposed) throw new ObjectDisposedException("音效播放器");
        string extension=System.IO.Path.GetExtension(source).ToLowerInvariant();
        if(extension!=".wav" && extension!=".mp3") throw new InvalidOperationException("请选择 WAV 或 MP3 音频。");
        Directory.CreateDirectory(managed);
        string relative=System.IO.Path.Combine("自定义音效",(open ? "开麦-" : "关麦-")+Guid.NewGuid().ToString("N")+extension);
        string path=Resolve(relative),old=SavedFile(open),oldName=open ? prefs.OpenSoundName : prefs.CloseSoundName;
        AudioCue candidate=null;
        try {
            File.Copy(source,path); candidate=await AudioCue.LoadAsync(path);
            if(disposed) throw new ObjectDisposedException("音效播放器");
            SetFile(open,relative,System.IO.Path.GetFileName(source));
            try { save(); } catch { SetFile(open,old,oldName); throw; }
            int index=open ? 0 : 1;
            if(custom[index]!=null) custom[index].Dispose(); custom[index]=candidate; candidate=null; errors[index]=null;
            DeleteOld(old);
        } catch { if(candidate!=null) candidate.Dispose(); try { File.Delete(path); } catch {} throw; }
    }
    public async Task RestoreAsync(bool open)
    {
        await ready.Task; if(disposed) throw new ObjectDisposedException("音效播放器");
        string old=SavedFile(open),oldName=open ? prefs.OpenSoundName : prefs.CloseSoundName;
        SetFile(open,"",""); try { save(); } catch { SetFile(open,old,oldName); throw; }
        int index=open ? 0 : 1; if(custom[index]!=null) { custom[index].Dispose(); custom[index]=null; } errors[index]=null; DeleteOld(old);
    }
    public void Dispose() { disposed=true; foreach(var cue in defaults.Concat(custom)) if(cue!=null) cue.Dispose(); }
    public static async Task<string> SelfTestAsync(string directory,string mp3)
    {
        Directory.CreateDirectory(directory);
        string defaultsRoot=AppDomain.CurrentDomain.BaseDirectory;
        foreach(string file in new string[] {"开麦.wav","关麦.wav"}) File.Copy(System.IO.Path.Combine(defaultsRoot,file),System.IO.Path.Combine(directory,file));
        string wave=System.IO.Path.Combine(directory,"选择的开麦.wav"),compressed=System.IO.Path.Combine(directory,"选择的关麦.mp3"),broken=System.IO.Path.Combine(directory,"损坏.mp3");
        File.Copy(System.IO.Path.Combine(directory,"开麦.wav"),wave); File.Copy(mp3,compressed); File.WriteAllText(broken,"not an audio file");
        var preferences=new Preferences(); var json=new JavaScriptSerializer();
        string settings=System.IO.Path.Combine(directory,"设置.json"); bool failSave=false;
        Action saveSettings=delegate { if(failSave) throw new IOException("simulated save failure"); File.WriteAllText(settings,json.Serialize(preferences)); };
        var lines=new List<string>(); var bank=new AudioBank(directory,preferences,saveSettings);
        try {
            await bank.InitializeAsync();
            await bank.ImportAsync(true,wave); await bank.ImportAsync(false,compressed);
            if(!bank.Name(true).StartsWith("选择的开麦.wav") || !bank.Name(false).StartsWith("选择的关麦.mp3")) throw new Exception("import labels");
            string open=preferences.OpenSoundFile,close=preferences.CloseSoundFile;
            if(!File.ReadAllBytes(wave).SequenceEqual(File.ReadAllBytes(System.IO.Path.Combine(directory,open))) || !File.ReadAllBytes(compressed).SequenceEqual(File.ReadAllBytes(System.IO.Path.Combine(directory,close)))) throw new Exception("managed copy");
            lines.Add("PASS: WAV and MP3 decoded, separate managed copies and saved choices");
            File.Delete(compressed);
            bool rejected=false; try { await bank.ImportAsync(true,broken); } catch { rejected=true; }
            if(!rejected || preferences.OpenSoundFile!=open || preferences.CloseSoundFile!=close) throw new Exception("corrupt import replaced working cue");
            lines.Add("PASS: corrupt audio rejected without replacing either cue");
            string originalSettings=File.ReadAllText(settings); failSave=true; rejected=false;
            try { await bank.ImportAsync(true,wave); } catch(IOException) { rejected=true; } finally { failSave=false; }
            if(!rejected || preferences.OpenSoundFile!=open || File.ReadAllText(settings)!=originalSettings) throw new Exception("failed save changed selection");
            lines.Add("PASS: settings save failure preserves previous selection");
            bank.Dispose(); preferences=json.Deserialize<Preferences>(File.ReadAllText(settings)); bank=new AudioBank(directory,preferences,saveSettings); await bank.InitializeAsync();
            if(bank.Name(false)!="选择的关麦.mp3" || bank.Name(true)!="选择的开麦.wav") throw new Exception("reload after source removed");
            lines.Add("PASS: saved audio reloads after original source was removed");
            await bank.RestoreAsync(true);
            if(preferences.OpenSoundFile!="" || preferences.CloseSoundFile!=close || !bank.Name(true).StartsWith("默认")) throw new Exception("independent restore");
            if(File.Exists(System.IO.Path.Combine(directory,open))) throw new Exception("unused custom audio not cleaned");
            if(!File.ReadAllBytes(wave).SequenceEqual(File.ReadAllBytes(System.IO.Path.Combine(directory,"开麦.wav")))) throw new Exception("default changed");
            await bank.RestoreAsync(false);
            if(Directory.GetFiles(System.IO.Path.Combine(directory,"自定义音效")).Length!=0) throw new Exception("failed import left managed files");
            lines.Add("PASS: independent restore, defaults preserved, unused managed files cleaned");
            return String.Join(Environment.NewLine,lines);
        } finally { bank.Dispose(); }
    }
}

internal sealed class SettingsActions
{
    public Func<Task> CheckUpdate;
    public Func<string> UpdateStatus;
    public Func<bool> UpdateBusy;
    public Action Apply, ResetPosition, PreviewOpen, PreviewClose, Diagnose, Help;
    public Func<bool> AutoStart;
    public Action<bool> SetAutoStart;
    public Func<string> Status;
    public Func<bool,string> SoundName;
    public Func<bool,string,Task> ImportSound;
    public Func<bool,Task> RestoreSound;
}

internal sealed class SettingsWindow : Window
{
    private readonly Preferences prefs;
    private readonly SettingsActions actions;
    private readonly StackPanel sections=new StackPanel();
    private readonly List<Action> soundSync=new List<Action>();
    private readonly TextBlock feedback=new TextBlock();
    private readonly DispatcherTimer refresh=new DispatcherTimer();
    private readonly ScrollViewer scroll;
    private CheckBox show;
    private bool syncing;
    private static SolidColorBrush Color(string color) { return (SolidColorBrush)new BrushConverter().ConvertFromString(color); }
    private static TextBlock Label(string text,double size,string color)
    {
        return new TextBlock { Text=text,FontSize=size,Foreground=Color(color),TextWrapping=TextWrapping.Wrap,VerticalAlignment=VerticalAlignment.Center };
    }
    public static System.Windows.Controls.Button MakeButton(string title)
    {
        var button=new System.Windows.Controls.Button { Content=title,Foreground=Color("#EDF0F7"),Background=Color("#343844"),BorderThickness=new Thickness(0),Padding=new Thickness(13,7,13,7),Cursor=System.Windows.Input.Cursors.Hand,FontSize=12 };
        button.Template=(ControlTemplate)System.Windows.Markup.XamlReader.Parse("<ControlTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' TargetType='Button'><Border x:Name='frame' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' Background='{TemplateBinding Background}' CornerRadius='6' Padding='{TemplateBinding Padding}'><ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/></Border><ControlTemplate.Triggers><Trigger Property='IsMouseOver' Value='True'><Setter TargetName='frame' Property='Background' Value='#454B59'/></Trigger><Trigger Property='IsPressed' Value='True'><Setter TargetName='frame' Property='Background' Value='#52615C'/></Trigger><Trigger Property='IsEnabled' Value='False'><Setter TargetName='frame' Property='Opacity' Value='0.45'/></Trigger></ControlTemplate.Triggers></ControlTemplate>");
        return button;
    }
    public SettingsWindow(Preferences preferences,SettingsActions callbacks)
    {
        prefs=preferences; actions=callbacks;
        Title="YY 语音助手 · 设置"; Width=560; Height=Math.Min(780,SystemParameters.WorkArea.Height-32);
        MinWidth=480; MinHeight=420; WindowStartupLocation=WindowStartupLocation.CenterScreen;
        WindowStyle=WindowStyle.None; AllowsTransparency=true; Background=System.Windows.Media.Brushes.Transparent;
        ResizeMode=ResizeMode.NoResize; ShowInTaskbar=true; FontFamily=new FontFamily("Microsoft YaHei UI");
        var grid=new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto });
        var header=new Grid { Margin=new Thickness(24,19,18,16) };
        header.ColumnDefinitions.Add(new ColumnDefinition()); header.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var titles=new StackPanel(); titles.Children.Add(Label("设置",23,"#F4F6FA"));
        var subtitle=Label("YY 语音助手",11,"#989EAD"); subtitle.Margin=new Thickness(0,5,0,0); titles.Children.Add(subtitle); header.Children.Add(titles);
        titles.MouseLeftButtonDown+=delegate { try { DragMove(); } catch(InvalidOperationException) {} };
        var close=MakeButton("×"); close.Width=32; close.Height=30; close.Padding=new Thickness(0); close.VerticalAlignment=VerticalAlignment.Top; close.ToolTip="关闭设置";
        close.Click+=delegate { Close(); }; Grid.SetColumn(close,1); header.Children.Add(close); grid.Children.Add(header);
        scroll=new ScrollViewer { Content=sections,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled,Margin=new Thickness(20,0,20,0) };
        Grid.SetRow(scroll,1); grid.Children.Add(scroll);

        var overlay=Section("悬浮窗");
        show=Toggle(overlay,"显示悬浮窗",!prefs.Hidden,delegate(bool value) { prefs.Hidden=!value; Apply(); });
        Toggle(overlay,"靠近屏幕左右边缘时自动收起",prefs.AutoDock,delegate(bool value) { prefs.AutoDock=value; Apply(); });
        Toggle(overlay,"锁定位置，并让鼠标点击穿过悬浮窗",prefs.Locked,delegate(bool value) { prefs.Locked=value; Apply(); });
        var opacityRow=new Grid { Margin=new Thickness(0,10,0,4) };
        opacityRow.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(92) }); opacityRow.ColumnDefinitions.Add(new ColumnDefinition()); opacityRow.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(48) });
        opacityRow.Children.Add(Label("不透明度",12,"#DDE0E8"));
        var opacity=new Slider { Minimum=50,Maximum=100,Value=Math.Round(prefs.Opacity*100),TickFrequency=1,IsSnapToTickEnabled=true,VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(0,0,12,0) };
        var percentage=Label(((int)opacity.Value)+"%",12,"#A3E0BE"); Grid.SetColumn(opacity,1); Grid.SetColumn(percentage,2); opacityRow.Children.Add(opacity); opacityRow.Children.Add(percentage); overlay.Children.Add(opacityRow);
        opacity.ValueChanged+=delegate { percentage.Text=((int)opacity.Value)+"%"; prefs.Opacity=opacity.Value/100; Apply(); };
        AddButton(overlay,"找回悬浮窗 / 重置位置",delegate { Run(delegate { actions.ResetPosition(); Synchronize(); },"悬浮窗已显示，并恢复到屏幕左上方。"); });

        var members=Section("频道成员");
        int lastLimit=prefs.MaxMembers==0 ? 6 : prefs.MaxMembers;
        var countRow=new DockPanel { Margin=new Thickness(0,8,0,3) };
        var count= new TextBox { Text=lastLimit.ToString(),Width=54,FontSize=13,Padding=new Thickness(6,4,6,4),TextAlignment=TextAlignment.Center,Background=Color("#191C24"),Foreground=Color("#EDF0F7"),BorderBrush=Color("#4C5262"),VerticalContentAlignment=VerticalAlignment.Center };
        var unlimited=new CheckBox { Content="不限人数",IsChecked=prefs.MaxMembers==0,Foreground=Color("#DDE0E8"),FontSize=12,VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(16,0,0,0) };
        var countLabel=Label("最多显示人数",12,"#DDE0E8"); countLabel.Width=112; countRow.Children.Add(countLabel); countRow.Children.Add(count); countRow.Children.Add(unlimited); members.Children.Add(countRow);
        var countNote=Label("可填写 1–50 人，超出上限的成员用 … 表示。",11,"#989EAD"); countNote.Margin=new Thickness(0,5,0,8); members.Children.Add(countNote);
        count.IsEnabled=prefs.MaxMembers!=0;
        count.TextChanged+=delegate {
            int value;
            if(!Int32.TryParse(count.Text,out value) || value<1 || value>50) { countNote.Text="请输入 1–50 之间的整数。"; countNote.Foreground=Color("#EEA2AD"); return; }
            lastLimit=value; countNote.Text="超出上限的成员用 … 表示。"; countNote.Foreground=Color("#989EAD");
            if(unlimited.IsChecked!=true) { prefs.MaxMembers=value; Apply(); }
        };
        unlimited.Checked+=delegate { count.IsEnabled=false; prefs.MaxMembers=0; Apply(); };
        unlimited.Unchecked+=delegate { count.IsEnabled=true; count.Text=lastLimit.ToString(); prefs.MaxMembers=lastLimit; Apply(); };
        Toggle(members,"人数超过上限时，正在说话的成员优先显示",prefs.PrioritizeSpeakers,delegate(bool value) { prefs.PrioritizeSpeakers=value; Apply(); });

        var sound=Section("开关麦提示音");
        Toggle(sound,"播放开麦和关麦提示音",prefs.Sound,delegate(bool value) { prefs.Sound=value; Apply(); });
        var formats=Label("支持 WAV、MP3；选好的音频会保存到助手目录。",11,"#989EAD"); formats.Margin=new Thickness(0,0,0,4); sound.Children.Add(formats);
        AddSoundRow(sound,true); AddSoundRow(sound,false);

        var startup=Section("启动与帮助");
        var auto=Toggle(startup,"打开 YY 时自动启动助手",actions.AutoStart(),delegate(bool value) {});
        Action setAuto=delegate {
            if(syncing) return;
            try { actions.SetAutoStart(auto.IsChecked==true); feedback.Text="启动设置已保存。"; }
            catch(Exception ex) { feedback.Text="启动设置未保存："+ex.Message; }
            syncing=true; auto.IsChecked=actions.AutoStart(); syncing=false;
        };
        auto.Checked+=delegate { setAuto(); }; auto.Unchecked+=delegate { setAuto(); };
        var startupNote=Label("登录 Windows 后在后台等待，检测到 YY 启动时再打开助手。",11,"#989EAD"); startupNote.Margin=new Thickness(0,0,0,8); startup.Children.Add(startupNote);
        var connection=Label(actions.Status(),11,"#A3E0BE"); connection.Margin=new Thickness(0,4,0,8); startup.Children.Add(connection);
        var tools=new StackPanel { Orientation=Orientation.Horizontal };
        var diagnose=MakeButton("保存状态诊断"); diagnose.Margin=new Thickness(0,0,10,0); diagnose.Click+=delegate { Run(actions.Diagnose,"状态诊断已保存到工具目录。"); };
        var help=MakeButton("使用说明"); help.Click+=delegate { Run(actions.Help,"已打开使用说明。"); }; tools.Children.Add(diagnose); tools.Children.Add(help); startup.Children.Add(tools);

        var updates=Section("检查更新");
        updates.Children.Add(Label("当前版本  v"+Updates.VersionLabel,12,"#DDE0E8"));
        Toggle(updates,"有新版本时自动下载并更新",prefs.AutoUpdate,delegate(bool value) { prefs.AutoUpdate=value; Apply(); });
        var updateNote=Label("启动后检查，每 6 小时检查一次；更新时保留设置与提示音，并重新启动助手。",11,"#989EAD");
        updateNote.Margin=new Thickness(0,0,0,8); updates.Children.Add(updateNote);
        var updateStatus=Label(actions.UpdateStatus==null ? "尚未检查更新" : actions.UpdateStatus(),11,"#A3E0BE"); updates.Children.Add(updateStatus);
        var updateButtons=new StackPanel { Orientation=Orientation.Horizontal,Margin=new Thickness(0,10,0,0) };
        var checkUpdate=MakeButton("检查更新"); checkUpdate.Margin=new Thickness(0,0,10,0);
        checkUpdate.Click+=async delegate {
            checkUpdate.IsEnabled=false;
            try { if(actions.CheckUpdate!=null) await actions.CheckUpdate(); }
            catch(Exception ex) { feedback.Text="更新未完成："+ex.Message; }
            finally { checkUpdate.IsEnabled=true; if(actions.UpdateStatus!=null) updateStatus.Text=actions.UpdateStatus(); }
        };
        var releasePage=MakeButton("查看发布版本"); releasePage.Click+=delegate { Run(delegate { Process.Start(Updates.ReleasePage); },"已打开版本发布页。"); };
        updateButtons.Children.Add(checkUpdate); updateButtons.Children.Add(releasePage); updates.Children.Add(updateButtons);

        feedback.Text="设置即时生效并自动保存。关闭此窗口后，助手继续运行。";
        feedback.FontSize=11; feedback.Foreground=Color("#989EAD"); feedback.TextWrapping=TextWrapping.Wrap; feedback.Margin=new Thickness(24,13,24,17);
        Grid.SetRow(feedback,2); grid.Children.Add(feedback);
        Content=new Border { Background=Color("#191B23"),BorderBrush=Color("#454A59"),BorderThickness=new Thickness(1),CornerRadius=new CornerRadius(14),Child=grid };
        refresh.Interval=TimeSpan.FromSeconds(1); refresh.Tick+=delegate { connection.Text=actions.Status(); foreach(var sync in soundSync) sync(); if(actions.UpdateStatus!=null) updateStatus.Text=actions.UpdateStatus(); if(actions.UpdateBusy!=null) checkUpdate.IsEnabled=!actions.UpdateBusy(); }; refresh.Start();
        Activated+=delegate { Synchronize(); }; Closed+=delegate { refresh.Stop(); };
    }
    private StackPanel Section(string title)
    {
        var contents=new StackPanel(); var heading=Label(title,14,"#F0F3F8"); heading.FontWeight=FontWeights.SemiBold; heading.Margin=new Thickness(0,0,0,8); contents.Children.Add(heading);
        sections.Children.Add(new Border { Background=Color("#252832"),CornerRadius=new CornerRadius(10),Padding=new Thickness(16,11,16,11),Margin=new Thickness(0,0,0,10),Child=contents }); return contents;
    }
    private CheckBox Toggle(StackPanel panel,string title,bool value,Action<bool> changed)
    {
        var box=new CheckBox { Content=title,IsChecked=value,Foreground=Color("#DDE0E8"),FontSize=12,Margin=new Thickness(0,5,0,8) };
        box.Checked+=delegate { if(!syncing) changed(true); }; box.Unchecked+=delegate { if(!syncing) changed(false); }; panel.Children.Add(box); return box;
    }
    private void AddButton(StackPanel panel,string text,Action callback)
    {
        var button=MakeButton(text); button.HorizontalAlignment=HorizontalAlignment.Left; button.Margin=new Thickness(0,8,0,0); button.Click+=delegate { callback(); }; panel.Children.Add(button);
    }
    private void AddSoundRow(StackPanel panel,bool open)
    {
        var row=new StackPanel { Margin=new Thickness(0,8,0,6) };
        var heading=new DockPanel { Margin=new Thickness(0,0,0,7) };
        var title=Label(open ? "开麦" : "关麦",12,"#EDF0F7"); title.Width=48; heading.Children.Add(title);
        var name=Label(actions.SoundName(open),11,"#989EAD"); name.TextWrapping=TextWrapping.NoWrap; name.TextTrimming=TextTrimming.CharacterEllipsis;
        heading.Children.Add(name); row.Children.Add(heading);
        Action sync=delegate { name.Text=actions.SoundName(open); name.ToolTip=name.Text; }; soundSync.Add(sync);
        var buttons=new StackPanel { Orientation=Orientation.Horizontal };
        var choose=MakeButton("选择音频…"); var preview=MakeButton("试听"); var restore=MakeButton("恢复默认");
        choose.Margin=new Thickness(0,0,8,0); preview.Margin=new Thickness(0,0,8,0);
        buttons.Children.Add(choose); buttons.Children.Add(preview); buttons.Children.Add(restore); row.Children.Add(buttons); panel.Children.Add(row);
        preview.Click+=delegate { Run(open ? actions.PreviewOpen : actions.PreviewClose,"正在试听"+(open ? "开麦" : "关麦")+"提示音。"); };
        choose.Click+=async delegate {
            var dialog=new Microsoft.Win32.OpenFileDialog { Title="选择"+(open ? "开麦" : "关麦")+"提示音",Filter="音频文件 (*.wav;*.mp3)|*.wav;*.mp3|WAV 音频 (*.wav)|*.wav|MP3 音频 (*.mp3)|*.mp3",CheckFileExists=true,Multiselect=false };
            if(dialog.ShowDialog(this)!=true) return;
            buttons.IsEnabled=false; feedback.Text="正在检查并保存音频…";
            try { await actions.ImportSound(open,dialog.FileName); sync(); feedback.Text="提示音已保存，可以点击试听。"; }
            catch(Exception ex) { feedback.Text="音频未更换："+ex.Message; }
            finally { buttons.IsEnabled=true; }
        };
        restore.Click+=async delegate {
            buttons.IsEnabled=false;
            try { await actions.RestoreSound(open); sync(); feedback.Text="已恢复默认"+(open ? "开麦" : "关麦")+"提示音。"; }
            catch(Exception ex) { feedback.Text="恢复未完成："+ex.Message; }
            finally { buttons.IsEnabled=true; }
        };
    }
    private void Apply()
    {
        try { actions.Apply(); feedback.Text="设置已保存。"; }
        catch(Exception ex) { feedback.Text="未能保存："+ex.Message; }
    }
    private void Run(Action action,string success)
    {
        try { action(); feedback.Text=success; }
        catch(Exception ex) { feedback.Text="未完成："+ex.Message; }
    }
    public void PreviewScrollToEnd() { scroll.ScrollToVerticalOffset(scroll.ExtentHeight); UpdateLayout(); }
    public void Synchronize() { syncing=true; show.IsChecked=!prefs.Hidden; syncing=false; }
}

internal sealed class Assistant : IDisposable
{
    private readonly YYReader reader=new YYReader();
    private readonly Transition transition=new Transition();
    private readonly Preferences prefs;
    private readonly Overlay overlay;
    private readonly AudioBank soundBank;
    private readonly Updates updates;
    private readonly Forms.NotifyIcon tray;
    private Forms.ToolStripMenuItem showMenu;
    private SettingsWindow settings;
    private readonly CancellationTokenSource cancel=new CancellationTokenSource();
    private readonly DispatcherTimer raise=new DispatcherTimer();
    private readonly string root=AppDomain.CurrentDomain.BaseDirectory;
    private readonly JavaScriptSerializer json=new JavaScriptSerializer();
    private Snapshot latest=new Snapshot();
    private static readonly string SettingsPath=System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"设置.json");
    public Assistant(string tracePath, bool recover)
    {
        try { prefs=json.Deserialize<Preferences>(File.ReadAllText(SettingsPath)); } catch { prefs=new Preferences(); }
        if(prefs==null) prefs=new Preferences();
        if(recover) { prefs.Hidden=false; prefs.Locked=false; prefs.DockSide=""; prefs.X=30; prefs.Y=160; }
        if(prefs.Names==null) prefs.Names=new Dictionary<string,string>();
        if(prefs.MaxMembers<0 || prefs.MaxMembers>50) prefs.MaxMembers=6;
        prefs.Opacity=Math.Max(.5,Math.Min(1,prefs.Opacity));
        if(!Forms.Screen.AllScreens.Any(s=>s.WorkingArea.Contains((int)prefs.X+60,(int)prefs.Y+20))) { prefs.X=30; prefs.Y=160; }
        soundBank=new AudioBank(root,prefs,SaveChecked);
        updates=new Updates(prefs,SaveChecked);
        overlay=new Overlay(prefs);
        overlay.SettingsRequested+=OpenSettings;
        var menu=new Forms.ContextMenuStrip();
        var status=new Forms.ToolStripMenuItem("正在连接 YY") { Enabled=false }; menu.Items.Add(status);
        menu.Items.Add("设置…",null,delegate { OpenSettings(); });
        showMenu=new Forms.ToolStripMenuItem("显示悬浮窗") { Checked=!prefs.Hidden,CheckOnClick=true };
        showMenu.Click+=delegate {
            prefs.Hidden=!showMenu.Checked; overlay.ApplyPreferences(); Save();
            if(settings!=null) settings.Synchronize();
        }; menu.Items.Add(showMenu);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出助手",null,delegate { Application.Current.Shutdown(); });
        tray=new Forms.NotifyIcon { Icon=System.Drawing.SystemIcons.Information,Text="YY 语音助手",Visible=true,ContextMenuStrip=menu };
        tray.DoubleClick+=delegate { OpenSettings(); };
        if(!prefs.Hidden) overlay.Show();
        overlay.Dispatcher.BeginInvoke(new Action(async delegate { await soundBank.InitializeAsync(); }));
        string lastWindowReport="";
        raise.Interval=TimeSpan.FromSeconds(2); raise.Tick+=delegate {
            overlay.Raise();
            string report=json.Serialize(overlay.VisibilityReport());
            if(report!=lastWindowReport) {
                try { File.WriteAllText(System.IO.Path.Combine(root,"窗口诊断.json"),report); lastWindowReport=report; } catch { }
            }
        }; raise.Start();
        Task.Run(async delegate {
            string lastTrace="";
            while(!cancel.IsCancellationRequested) {
                var snapshot=reader.Poll(); MicChange change=transition.Observe(snapshot);
                bool play=change==MicChange.Closed;
                bool playOpen=change==MicChange.Opened;
                await Application.Current.Dispatcher.InvokeAsync(delegate {
                    latest=snapshot; overlay.Update(snapshot); status.Text=snapshot.Status;
                    tray.Text="YY · "+snapshot.Status;
                    if(play && prefs.Sound) soundBank.Play(false);
                    if(playOpen && prefs.Sound) soundBank.Play(true);
                    if(!String.IsNullOrEmpty(tracePath)) {
                        string line=json.Serialize(new { Status=snapshot.Status,Muted=snapshot.Muted,NativeMicFlag=snapshot.NativeMicFlag,Generation=snapshot.Generation,SpeakerCount=snapshot.Speakers.Count,Speakers=snapshot.Speakers,Members=snapshot.Members,RosterReadable=snapshot.RosterReadable,OpenSoundRequested=playOpen && prefs.Sound,CloseSoundRequested=play && prefs.Sound });
                        if(line!=lastTrace) {
                            try { File.AppendAllText(tracePath,DateTime.Now.ToString("O")+" "+line+Environment.NewLine); } catch { }
                            lastTrace=line;
                        }
                    }

                });
                try { await Task.Delay(80,cancel.Token); } catch(TaskCanceledException) { break; }
            }
        });
    }
    private void OpenSettings()
    {
        if(settings!=null) {
            if(settings.WindowState==WindowState.Minimized) settings.WindowState=WindowState.Normal;
            settings.Activate(); return;
        }
        settings=new SettingsWindow(prefs,new SettingsActions {
            CheckUpdate=updates.CheckAsync,UpdateStatus=delegate { return updates.Status; },UpdateBusy=delegate { return updates.Busy; },
            Apply=delegate { overlay.ApplyPreferences(); SaveChecked(); showMenu.Checked=!prefs.Hidden; },
            ResetPosition=delegate { prefs.Hidden=false; overlay.Show(); overlay.ResetPosition(); overlay.Raise(); SaveChecked(); showMenu.Checked=true; },
            PreviewOpen=delegate { soundBank.Play(true); }, PreviewClose=delegate { soundBank.Play(false); },
            SoundName=soundBank.Name,ImportSound=soundBank.ImportAsync,RestoreSound=soundBank.RestoreAsync,
            AutoStart=delegate { return YYStartup.Enabled; }, SetAutoStart=delegate(bool value) { YYStartup.SetEnabled(value); },
            Status=delegate { return latest.Status+" · "+(latest.RosterReadable ? latest.Members.Count+" 位成员" : "正在读取成员"); },
            Diagnose=delegate { File.WriteAllText(System.IO.Path.Combine(root,"状态诊断.json"),json.Serialize(new { Snapshot=latest,Window=overlay.VisibilityReport(),Settings=prefs,AutoStart=YYStartup.Enabled })); },
            Help=delegate { Process.Start(System.IO.Path.Combine(root,"使用说明.txt")); }
        });
        settings.Closed+=delegate { settings=null; }; settings.Show(); settings.Activate();
    }
    private void SaveChecked() { File.WriteAllText(SettingsPath,json.Serialize(prefs)); }
    private void Save() { try { SaveChecked(); } catch {} }
    public void Dispose() { cancel.Cancel(); raise.Stop(); updates.Dispose(); if(settings!=null) settings.Close(); overlay.SavePosition(); Save(); tray.Visible=false; tray.Dispose(); soundBank.Dispose(); }

}

internal sealed class YYLaunchTracker
{
    private string last="";
    public bool Observe(string generation)
    {
        bool launch=generation.Length>0 && generation!=last;
        last=generation; return launch;
    }
}

internal static class YYStartup
{
    private static readonly string Root=AppDomain.CurrentDomain.BaseDirectory;
    private static readonly string Exe=System.IO.Path.Combine(Root,"YY语音助手.exe");
    private static readonly string Shortcut=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup),"YY语音助手（随YY启动）.lnk");
    private const string WatchStop="Local\\YYVoiceAssistant959.WatcherStop";
    public static bool Enabled { get { return File.Exists(Shortcut); } }
    public static void Signal(string name)
    {
        try { using(var stop=EventWaitHandle.OpenExisting(name)) stop.Set(); }
        catch(WaitHandleCannotBeOpenedException) {}
    }
    public static void CreateShortcut(string path)
    {
        object shell=null,link=null;
        try {
            shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell",true));
            link=shell.GetType().InvokeMember("CreateShortcut",System.Reflection.BindingFlags.InvokeMethod,null,shell,new object[] { path });
            var properties=new Dictionary<string,object> {
                {"TargetPath",Exe},{"Arguments","--watch-yy"},{"WorkingDirectory",Root},
                {"Description","YY 启动后自动打开语音助手"},{"WindowStyle",1},{"IconLocation",Exe+",0"}
            };
            foreach(var entry in properties)
                link.GetType().InvokeMember(entry.Key,System.Reflection.BindingFlags.SetProperty,null,link,new object[] { entry.Value });
            link.GetType().InvokeMember("Save",System.Reflection.BindingFlags.InvokeMethod,null,link,null);
        }
        finally {
            if(link!=null) Marshal.FinalReleaseComObject(link);
            if(shell!=null) Marshal.FinalReleaseComObject(shell);
        }
    }
    public static void SetEnabled(bool enabled)
    {
        if(enabled) {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Shortcut));
            CreateShortcut(Shortcut);
            EnsureWatcher();
        } else { if(File.Exists(Shortcut)) File.Delete(Shortcut); Signal(WatchStop); }
    }
    public static void EnsureWatcher()
    {
        using(var process=Process.Start(new ProcessStartInfo(Exe,"--watch-yy") { UseShellExecute=false,WorkingDirectory=Root })) {}
    }
    public static int StopForUpdate()
    {
        Signal(WatchStop); Signal("Local\\YYVoiceAssistant959.Stop");
        int session=Process.GetCurrentProcess().SessionId, ownId=Process.GetCurrentProcess().Id;
        var deadline=DateTime.UtcNow.AddSeconds(6);
        while(DateTime.UtcNow<deadline) {
            bool running=false;
            foreach(var process in Process.GetProcessesByName("YY语音助手").Concat(Process.GetProcessesByName("YY语音助手-贴边版"))) {
                using(process) { try { if(process.Id!=ownId && process.SessionId==session && !process.HasExited) running=true; } catch(InvalidOperationException) {} }
            }
            if(!running) return 0;
            Thread.Sleep(100);
        }
        return 1;
    }
    public static int Watch()
    {
        bool created;
        using(var mutex=new Mutex(true,"Local\\YYVoiceAssistant959.Watcher",out created)) {
            if(!created) return 0;
            using(var stop=new EventWaitHandle(false,EventResetMode.ManualReset,WatchStop)) {
                var tracker=new YYLaunchTracker();
                int session=Process.GetCurrentProcess().SessionId, ownId=Process.GetCurrentProcess().Id;
                while(!stop.WaitOne(0)) {
                    try {
                        var ids=new List<string>();
                        foreach(var process in Process.GetProcessesByName("YY")) {
                            using(process) { try {
                                if(process.SessionId!=session || process.HasExited) continue;
                                string id=process.Id.ToString();
                                try { id+=":"+process.StartTime.ToUniversalTime().Ticks; } catch(System.ComponentModel.Win32Exception) {}
                                ids.Add(id);
                            } catch(InvalidOperationException) {} }
                        }
                        ids.Sort(StringComparer.Ordinal);
                        if(tracker.Observe(String.Join("|",ids))) {
                            bool running=false;
                            foreach(var process in Process.GetProcessesByName("YY语音助手")) {
                                using(process) { try { if(process.Id!=ownId && process.SessionId==session && !process.HasExited) running=true; } catch(InvalidOperationException) {} }
                            }
                            if(!running) Process.Start(new ProcessStartInfo(Exe) { UseShellExecute=false,WorkingDirectory=Root });
                        }
                    } catch(Exception ex) {
                        try { File.WriteAllText(System.IO.Path.Combine(Root,"随YY启动诊断.txt"),DateTime.Now.ToString("O")+" "+ex.Message); } catch {}
                    }
                    if(stop.WaitOne(1500)) break;
                }
            }
        }
        return 0;
    }
}

internal static class Program
{
    [STAThread] static int Main(string[] args)
    {
        if(IntPtr.Size!=8) return 2;
        if(args.Length>1 && args[0]=="--apply-update") return Updates.Apply(args[1]);
        if(args.Length>1 && args[0]=="--update-self-test") {
            try { File.WriteAllText(args[1],Updates.SelfTest()); return 0; }
            catch(Exception ex) { File.WriteAllText(args[1],"FAIL: "+ex); return 1; }
        }
        if(args.Length>1 && args[0]=="--probe-release") {
            try { File.WriteAllText(args[1],Updates.ProbeRelease()); return 0; }
            catch(Exception ex) { File.WriteAllText(args[1],"FAIL: "+ex); return 1; }
        }
        if(args.Length>1 && args[0]=="--verify-state") {
            int seconds=30; if(args.Length>2) Int32.TryParse(args[2],out seconds);
            seconds=Math.Max(5,Math.Min(120,seconds));
            var serializer=new JavaScriptSerializer(); var transition=new Transition();
            int polls=0,unknown=0,rosters=0,speakers=0,opened=0,closed=0;
            using(var reader=new YYReader()) using(var output=new StreamWriter(args[1],false,Encoding.UTF8)) {
                var deadline=DateTime.UtcNow.AddSeconds(seconds); string last="";
                while(DateTime.UtcNow<deadline) {
                    var snapshot=reader.Poll(); var change=transition.Observe(snapshot); polls++;
                    if(!snapshot.Muted.HasValue) unknown++;
                    if(snapshot.RosterReadable) rosters++;
                    if(snapshot.SpeakersReadable) speakers++;
                    if(change==MicChange.Opened) opened++; if(change==MicChange.Closed) closed++;
                    string data=serializer.Serialize(snapshot);
                    if(data!=last || change!=MicChange.None) {
                        output.WriteLine(serializer.Serialize(new {Time=DateTime.UtcNow.ToString("O"),Change=change.ToString(),State=snapshot})); output.Flush(); last=data;
                    }
                    Thread.Sleep(80);
                }
                output.WriteLine(serializer.Serialize(new {Summary=true,Polls=polls,Unknown=unknown,RosterReadable=rosters,SpeakersReadable=speakers,Opened=opened,Closed=closed}));
            }
            return unknown==0 ? 0 : 3;
        }
        if(args.Length>2 && args[0]=="--audio-self-test") {
            int result=1; var app=new Application { ShutdownMode=ShutdownMode.OnExplicitShutdown };
            app.Dispatcher.BeginInvoke(new Action(async delegate {
                try {
                    string directory=System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(args[1])),"custom-audio-test-"+Guid.NewGuid().ToString("N"));
                    string report=await AudioBank.SelfTestAsync(directory,args[2]); File.WriteAllText(args[1],report); result=0;
                } catch(Exception ex) { File.WriteAllText(args[1],"FAIL: "+ex); }
                finally { app.Shutdown(); }
            }));
            app.Run(); return result;
        }
        if(args.Length>0 && args[0]=="--watch-yy") return YYStartup.Watch();
        if(args.Length>0 && args[0]=="--stop-for-update") return YYStartup.StopForUpdate();
        if(args.Length>0 && (args[0]=="--enable-autostart" || args[0]=="--disable-autostart")) {
            try { YYStartup.SetEnabled(args[0]=="--enable-autostart"); return 0; }
            catch(Exception ex) { Forms.MessageBox.Show("设置失败："+ex.Message,"YY 语音助手"); return 1; }
        }
        if(args.Length>1 && args[0]=="--test-startup-link") { YYStartup.CreateShortcut(args[1]); return 0; }
        if(args.Length>0 && args[0]=="--exit") {
            try { using(var signal=EventWaitHandle.OpenExisting("Local\\YYVoiceAssistant959.Stop")) signal.Set(); return 0; }
            catch(WaitHandleCannotBeOpenedException) { return 3; }
        }
        if(args.Length>1 && args[0]=="--render-settings") {
            var app=new Application(); Action noOp=delegate {};
            var settings=new SettingsWindow(new Preferences(),new SettingsActions {
                Apply=noOp,ResetPosition=noOp,PreviewOpen=noOp,PreviewClose=noOp,Diagnose=noOp,Help=noOp,
                AutoStart=delegate { return false; },SetAutoStart=delegate(bool enabled) {},Status=delegate { return "已连接 YY · 9 位成员（预览示例）"; },
                SoundName=delegate(bool open) { return open ? "默认 · 上行提示音" : "默认 · 下行提示音"; },
                ImportSound=delegate(bool open,string path) { return Task.FromResult(0); },RestoreSound=delegate(bool open) { return Task.FromResult(0); }
            });
            var visual=(FrameworkElement)settings.Content;
            visual.Width=settings.Width; visual.Height=settings.Height;
            visual.Measure(new Size(settings.Width,settings.Height)); visual.Arrange(new Rect(0,0,settings.Width,settings.Height)); visual.UpdateLayout();
            if(args.Contains("--bottom")) settings.PreviewScrollToEnd();
            var bitmap=new System.Windows.Media.Imaging.RenderTargetBitmap((int)Math.Ceiling(settings.Width),(int)Math.Ceiling(settings.Height),96,96,PixelFormats.Pbgra32);
            bitmap.Render(visual); var encoder=new System.Windows.Media.Imaging.PngBitmapEncoder(); encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using(var file=File.Create(args[1])) encoder.Save(file); settings.Close(); return 0;
        }
        if(args.Length>1 && (args[0]=="--render" || args[0]=="--render-compact")) {
            var app=new Application();
            using(var reader=new YYReader()) {
                bool demo=args.Contains("--demo-overflow");
                var overlay=new Overlay(new Preferences { DockSide=args[0]=="--render-compact" ? "Left" : "",MaxMembers=demo ? 3 : 6 });
                var snapshot=reader.Poll();
                if(demo) {
                    snapshot=new Snapshot { Status="麦克风已关闭",Muted=true,RosterReadable=true,SpeakersReadable=true };
                    string[] names={"晨风","晴空","晚风","Moon","阿橙","小雨","星河","麦田","青禾"};
                    for(int i=0;i<names.Length;i++) snapshot.Members.Add(new Member { Uid=(ulong)i+1,Name=names[i] });
                    snapshot.Speakers.AddRange(new ulong[] {8,9});
                }
                overlay.Update(snapshot);
                var visual=(FrameworkElement)overlay.Content;
                visual.Width=overlay.Width; visual.Measure(new Size(overlay.Width,Double.PositiveInfinity));
                visual.Arrange(new Rect(new Point(0,0),visual.DesiredSize)); visual.UpdateLayout();
                var bitmap=new System.Windows.Media.Imaging.RenderTargetBitmap((int)Math.Ceiling(visual.ActualWidth),(int)Math.Ceiling(visual.ActualHeight),96,96,PixelFormats.Pbgra32);
                bitmap.Render(visual);
                var encoder=new System.Windows.Media.Imaging.PngBitmapEncoder();
                encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
                using(var f=File.Create(args[1])) encoder.Save(f);
            }
            return 0;
        }
        if(args.Length>0 && args[0]=="--probe") {
            using(var reader=new YYReader()) {
                var s=reader.Poll();
                File.WriteAllText(args.Length>1 ? args[1] : "状态诊断.json",new JavaScriptSerializer().Serialize(s));
                return s.Muted.HasValue ? 0 : 3;
            }
        }
        if(args.Length>0 && args[0]=="--self-test") {
            var t=new Transition();
            Func<bool,string,Snapshot> s=(m,g)=>new Snapshot { Muted=m,Generation=g };
            bool ok=t.Observe(s(false,"a"))==MicChange.None && t.Observe(s(false,"a"))==MicChange.None && t.Observe(s(true,"a"))==MicChange.None && t.Observe(s(true,"a"))==MicChange.Closed && t.Observe(s(true,"a"))==MicChange.None;
            ok=ok && t.Observe(new Snapshot())==MicChange.None && t.Observe(s(true,"b"))==MicChange.None && t.Observe(s(true,"b"))==MicChange.None;
            ok=ok && t.Observe(s(false,"b"))==MicChange.None && t.Observe(s(false,"b"))==MicChange.Opened && t.Observe(s(true,"b"))==MicChange.None && t.Observe(s(true,"b"))==MicChange.Closed;
            var launch=new YYLaunchTracker();
            ok=ok && !launch.Observe("") && launch.Observe("1:a") && !launch.Observe("1:a") && !launch.Observe("") && launch.Observe("2:b") && !launch.Observe("2:b");
            ok=ok && MemberDisplay.SelfTest();
            File.WriteAllText(args.Length>1 ? args[1] : "自检.txt",ok ? "PASS: mic transitions and reconnect; YY startup and manual exit; member cap, hidden speakers promoted, simultaneous speakers, speaking ends, unlimited, unreadable and empty roster" : "FAIL");
            return ok ? 0 : 1;
        }
        bool created;
        using(var mutex=new Mutex(true,"Local\\YYVoiceAssistant959",out created)) {
            if(!created) return 0;
            var app=new Application { ShutdownMode=ShutdownMode.OnExplicitShutdown };
            var stop=new EventWaitHandle(false,EventResetMode.ManualReset,"Local\\YYVoiceAssistant959.Stop");
            var stopWait=ThreadPool.RegisterWaitForSingleObject(stop,delegate { app.Dispatcher.BeginInvoke(new Action(delegate { app.Shutdown(); })); },null,Timeout.Infinite,true);
            Assistant assistant=null;
            try {
                assistant=new Assistant(args.Length>1 && args[0]=="--trace" ? args[1] : null, args.Contains("--recover"));
                if(args.Length>1 && args[0]=="--update-ready") {
                    string readyPath=System.IO.Path.GetFullPath(args[1]);
                    string updateRoot=System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".更新")+System.IO.Path.DirectorySeparatorChar;
                    if(readyPath.StartsWith(updateRoot,StringComparison.OrdinalIgnoreCase))
                        app.Dispatcher.BeginInvoke(new Action(delegate { File.WriteAllText(readyPath,"ready"); }));
                }
                if(YYStartup.Enabled) { try { YYStartup.EnsureWatcher(); } catch(Exception ex) { File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"随YY启动诊断.txt"),ex.Message); } }
                app.Run();
            }
            catch(Exception ex) { if(args.Length==0 || args[0]!="--update-ready") Forms.MessageBox.Show(ex.Message,"YY 语音助手"); return 1; }
            finally { stopWait.Unregister(null); stop.Dispose(); if(assistant!=null) assistant.Dispose(); }
        }
        return 0;
    }
}
