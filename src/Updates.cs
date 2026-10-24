using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

internal sealed class ReleaseAsset
{
    public string name { get; set; }
    public string browser_download_url { get; set; }
    public long size { get; set; }
}
internal sealed class AppRelease
{
    public long id { get; set; }
    public string tag_name { get; set; }
    public bool draft { get; set; }
    public bool prerelease { get; set; }
    public ReleaseAsset[] assets { get; set; }
}
internal sealed class UpdatePlan
{
    public string Target, Hash, Version;
    public int Parent;
}

internal sealed class Updates : IDisposable
{
    public const string Repository="darlingqin/yy-voice-assistant";
    public const string ReleasePage="https://gitee.com/"+Repository+"/releases";
    public static readonly Version Current=Assembly.GetExecutingAssembly().GetName().Version;
    public static string VersionLabel { get { return Current.ToString(3); } }
    private readonly Preferences prefs;
    private readonly Action save;
    private readonly CancellationTokenSource cancellation=new CancellationTokenSource();
    private readonly System.Windows.Threading.DispatcherTimer timer=new System.Windows.Threading.DispatcherTimer();
    private int busy;
    private bool first=true;
    private volatile string status="尚未检查更新";
    public string Status { get { return status; } }
    public bool Busy { get { return busy!=0; } }
    public Updates(Preferences preferences,Action persist)
    {
        prefs=preferences; save=persist;
        string result=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"更新结果.txt");
        try { if(File.Exists(result)) status=File.ReadAllText(result); } catch { }
        timer.Interval=TimeSpan.FromSeconds(15);
        timer.Tick+=async delegate {
            if(first) { first=false; timer.Interval=TimeSpan.FromHours(6); }
            if(prefs.AutoUpdate) await CheckAsync();
        };
        timer.Start();
    }
    public async Task CheckAsync()
    {
        if(Interlocked.CompareExchange(ref busy,1,0)!=0) return;
        string stage=null;
        bool handedOff=false;
        try {
            status="正在检查更新…";
            var token=cancellation.Token;
            var release=await Task.Run(delegate {
                return LoadRelease(token);
            },token);
            Version version;
            if(release==null || release.draft || release.prerelease || !TryVersion(release.tag_name,out version))
                throw new InvalidDataException("发布版本信息不完整。");
            if(version<=Current) { status="当前已是最新版本 · v"+VersionLabel; return; }
            string name="YY-Voice-Assistant-v"+version.ToString(3)+"-win-x64.zip";
            var asset=FindAsset(release,name);
            var checksum=FindAsset(release,name+".sha256");
            if(asset.size<=0 || asset.size>128*1024*1024) throw new InvalidDataException("更新包大小不符合要求。");
            stage=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".更新",Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stage);
            string prepared=stage;
            status="发现 v"+version.ToString(3)+"，正在下载…";
            await Task.Run(delegate {
                string hash=ParseHash(Encoding.ASCII.GetString(Download(checksum.browser_download_url,4096,token,null)),name);
                byte[] package=Download(asset.browser_download_url,128*1024*1024,token,delegate(long done) {
                    status="正在下载 v"+version.ToString(3)+" · "+Math.Min(100,done*100/asset.size)+"%";
                });
                if(package.LongLength!=asset.size) throw new InvalidDataException("更新包下载不完整。");
                ValidateAndExtract(package,hash,version,prepared);
            },token);
            token.ThrowIfCancellationRequested();
            save();
            var plan=new UpdatePlan { Target=AppDomain.CurrentDomain.BaseDirectory,Hash=HashFile(Path.Combine(stage,"YY语音助手.exe")),Version=version.ToString(),Parent=Process.GetCurrentProcess().Id };
            string planPath=Path.Combine(stage,"plan.json");
            File.WriteAllText(planPath,new JavaScriptSerializer().Serialize(plan));
            string worker=Path.Combine(stage,"更新助手.exe");
            File.Copy(Assembly.GetExecutingAssembly().Location,worker);
            status="校验完成，正在更新并重新启动…";
            Process.Start(new ProcessStartInfo(worker,"--apply-update \""+planPath+"\"") { UseShellExecute=false,WorkingDirectory=stage,CreateNoWindow=true });
            handedOff=true;
        } catch(OperationCanceledException) { status="已取消检查更新。"; }
        catch(WebException ex) {
            var response=ex.Response as HttpWebResponse;
            status=response!=null && response.StatusCode==HttpStatusCode.NotFound ? "暂未发布可用版本。" : "无法检查更新，请检查网络后重试。";
            if(response!=null) response.Dispose();
        }
        catch(Exception ex) { status="更新未完成："+ex.Message; }
        finally { if(!handedOff) Interlocked.Exchange(ref busy,0); }
    }
    internal static bool TryVersion(string text,out Version result)
    {
        result=null;
        if(text==null || !Regex.IsMatch(text,@"^v?\d+\.\d+\.\d+(\.\d+)?$")) return false;
        Version parsed;
        if(!Version.TryParse(text.TrimStart('v'),out parsed)) return false;
        result=new Version(parsed.Major,parsed.Minor,parsed.Build,Math.Max(0,parsed.Revision)); return true;
    }
    private static AppRelease LoadRelease(CancellationToken token)
    {
        string api="https://gitee.com/api/v5/repos/"+Repository+"/releases/";
        string body=Encoding.UTF8.GetString(Download(api+"latest",1024*1024,token,null));
        var release=new JavaScriptSerializer().Deserialize<AppRelease>(body);
        Version version;
        if(release==null || release.id<=0 || release.draft || release.prerelease || !TryVersion(release.tag_name,out version))
            throw new InvalidDataException("发布版本信息不完整。");
        // Gitee latest-release assets omit size; retrieve and cross-check attachment metadata.
        string attachments=Encoding.UTF8.GetString(Download(api+release.id+"/attach_files?per_page=100",1024*1024,token,null));
        return MergeAttachments(release,attachments);
    }
    internal static AppRelease MergeAttachments(AppRelease release,string body)
    {
        var attachments=new JavaScriptSerializer().Deserialize<ReleaseAsset[]>(body);
        if(attachments==null || attachments.Length>=100) throw new InvalidDataException("发行版附件信息不完整。");
        foreach(var asset in attachments) {
            if(asset==null || asset.size<=0 || (release.assets ?? new ReleaseAsset[0]).Count(a=>a!=null && a.name==asset.name && a.browser_download_url==asset.browser_download_url)!=1)
                throw new InvalidDataException("发行版附件信息不一致。");
        }
        release.assets=attachments;
        return release;
    }
    private static ReleaseAsset FindAsset(AppRelease release,string name)
    {
        var matches=(release.assets ?? new ReleaseAsset[0]).Where(a=>a.name==name).ToArray();
        if(matches.Length!=1) throw new InvalidDataException("新版本缺少更新包或 SHA256 校验文件。");
        Uri uri;
        if(!Uri.TryCreate(matches[0].browser_download_url,UriKind.Absolute,out uri) || uri.Scheme!="https" || uri.Host!="gitee.com" ||
            !uri.AbsolutePath.StartsWith("/"+Repository+"/releases/download/"+release.tag_name+"/",StringComparison.Ordinal) || !String.IsNullOrEmpty(uri.Query) || !String.IsNullOrEmpty(uri.Fragment) || !String.IsNullOrEmpty(uri.UserInfo) || !uri.IsDefaultPort)
            throw new InvalidDataException("更新文件来源不正确。");
        return matches[0];
    }
    private static byte[] Download(string url,int limit,CancellationToken token,Action<long> progress)
    {
        ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
        var request=(HttpWebRequest)WebRequest.Create(url);
        request.UserAgent="YY-Voice-Assistant/"+VersionLabel;
        request.Accept="application/json, application/octet-stream";
        request.Timeout=20000; request.ReadWriteTimeout=20000;
        using(token.Register(request.Abort))
        using(var response=(HttpWebResponse)request.GetResponse()) {
            if(response.ResponseUri.Scheme!="https" || !(response.ResponseUri.Host=="gitee.com" || (response.ResponseUri.Host=="foruda.gitee.com" && response.ResponseUri.AbsolutePath.StartsWith("/attach_file/",StringComparison.Ordinal))))
                throw new InvalidDataException("更新下载被重定向到未知来源。");
            if(response.ContentLength>limit) throw new InvalidDataException("更新数据过大。");
            using(var stream=response.GetResponseStream())
            using(var buffer=new MemoryStream()) {
                var chunk=new byte[32768]; int count;
                while((count=stream.Read(chunk,0,chunk.Length))>0) {
                    token.ThrowIfCancellationRequested();
                    if(buffer.Length+count>limit) throw new InvalidDataException("更新数据过大。");
                    buffer.Write(chunk,0,count); if(progress!=null) progress(buffer.Length);
                }
                return buffer.ToArray();
            }
        }
    }
    internal static string ParseHash(string text,string name)
    {
        var match=Regex.Match(text.Trim(),@"\A([a-fA-F0-9]{64})[ \t]+\*?"+Regex.Escape(name)+@"\z");
        if(!match.Success) throw new InvalidDataException("校验文件格式不正确。");
        return match.Groups[1].Value.ToLowerInvariant();
    }
    internal static string HashFile(string file) { using(var sha=SHA256.Create()) using(var stream=File.OpenRead(file)) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant(); }
    internal static void ValidateAndExtract(byte[] bytes,string hash,Version version,string stage)
    {
        using(var sha=SHA256.Create())
            if(BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant()!=hash)
                throw new InvalidDataException("更新包 SHA256 校验失败，已保留当前版本。");
        var entries=new Dictionary<string,ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        string[] allowed={"YY语音助手.exe","开麦.wav","关麦.wav","使用说明.txt"};
        using(var stream=new MemoryStream(bytes)) using(var zip=new ZipArchive(stream,ZipArchiveMode.Read)) {
            long total=0;
            foreach(var entry in zip.Entries) {
                string name=entry.FullName;
                if(!allowed.Contains(name) || entries.ContainsKey(name) || entry.Length>64*1024*1024 || (total+=entry.Length)>128*1024*1024)
                    throw new InvalidDataException("更新包包含不允许的文件。");
                entries.Add(name,entry);
            }
            if(!allowed.All(entries.ContainsKey)) throw new InvalidDataException("更新包缺少必要文件。");
            Directory.CreateDirectory(stage);
            foreach(var item in entries) using(var source=item.Value.Open()) using(var target=File.Create(Path.Combine(stage,item.Key))) source.CopyTo(target);
        }
        VerifyExecutable(Path.Combine(stage,"YY语音助手.exe"),version);
    }
    internal static void VerifyExecutable(string path,Version version)
    {
        if(AssemblyName.GetAssemblyName(path).Version!=version || FileVersionInfo.GetVersionInfo(path).FileDescription!="YY Voice Assistant")
            throw new InvalidDataException("更新包中的程序或版本不匹配。");
    }
    // Only the executable is replaced. Existing default and imported sounds remain untouched.
    internal static void InstallFiles(string stage,string target,Action restart)
    {
        string exe=Path.Combine(target,"YY语音助手.exe"), incoming=exe+".incoming", backup=exe+".previous";
        bool replaced=false; var added=new List<string>();
        try {
            if(File.Exists(backup)) File.Delete(backup);
            File.Copy(Path.Combine(stage,"YY语音助手.exe"),incoming,true);
            File.Replace(incoming,exe,backup); replaced=true;
            foreach(string name in new[]{"开麦.wav","关麦.wav"}) {
                string path=Path.Combine(target,name);
                if(!File.Exists(path)) { File.Copy(Path.Combine(stage,name),path); added.Add(path); }
            }
            restart();
        } catch {
            if(replaced) File.Copy(backup,exe,true);
            foreach(string path in added) File.Delete(path);
            throw;
        } finally { if(File.Exists(incoming)) File.Delete(incoming); }
    }
    public static int Apply(string planPath)
    {
        bool created;
        using(var mutex=new Mutex(true,"Local\\YYVoiceAssistant959.Update",out created)) {
            return created ? ApplyCore(planPath) : 0;
        }
    }
    private static int ApplyCore(string planPath)
    {
        string target=null;
        try {
            string stage=AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            if(Path.GetFullPath(planPath)!=Path.Combine(stage,"plan.json")) throw new InvalidDataException("更新计划位置不正确。");
            var plan=new JavaScriptSerializer().Deserialize<UpdatePlan>(File.ReadAllText(planPath));
            string requestedTarget=Path.GetFullPath(plan.Target).TrimEnd(Path.DirectorySeparatorChar);
            if(Directory.GetParent(stage).Name!=".更新" || !String.Equals(Directory.GetParent(stage).Parent.FullName,requestedTarget,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("更新目标位置不正确。");
            for(var dir=new DirectoryInfo(stage); dir!=null; dir=dir.Parent)
                if((dir.Attributes&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException("更新目录不能是链接。");
            string candidate=Path.Combine(stage,"YY语音助手.exe");
            Version expected;
            if(!TryVersion(plan.Version,out expected) || HashFile(candidate)!=plan.Hash) throw new InvalidDataException("待安装程序校验失败。");
            VerifyExecutable(candidate,expected);
            target=requestedTarget;
            if(YYStartup.StopForUpdate()!=0) throw new IOException("助手未能退出，请稍后重试。");
            try { using(var parent=Process.GetProcessById(plan.Parent)) if(!parent.WaitForExit(8000)) throw new IOException("助手仍在退出，请稍后重试。"); }
            catch(ArgumentException) { }
            string root=target;
            InstallFiles(stage,target,delegate {
                File.WriteAllText(Path.Combine(root,"更新结果.txt"),"已更新至 v"+expected.ToString(3));
                string ready=Path.Combine(stage,"ready");
                if(File.Exists(ready)) File.Delete(ready);
                using(var launched=Process.Start(new ProcessStartInfo(Path.Combine(root,"YY语音助手.exe"),"--update-ready \""+ready+"\"") { UseShellExecute=false,WorkingDirectory=root })) {
                    var deadline=DateTime.UtcNow.AddSeconds(15);
                    while(DateTime.UtcNow<deadline) {
                        if(File.Exists(ready)) return;
                        if(launched.HasExited) throw new IOException("新版未能正常启动，已恢复旧版。");
                        Thread.Sleep(100);
                    }
                    YYStartup.StopForUpdate();
                    throw new IOException("新版启动超时，正在恢复旧版。");
                }
            });
            return 0;
        } catch(Exception ex) {
            if(target!=null) {
                try { File.WriteAllText(Path.Combine(target,"更新结果.txt"),"更新未完成："+ex.Message); } catch { }
                try { Process.Start(new ProcessStartInfo(Path.Combine(target,"YY语音助手.exe")) { UseShellExecute=false,WorkingDirectory=target }); } catch { }
            }
            return 1;
        }
    }
    public void Dispose() { timer.Stop(); cancellation.Cancel(); }

    internal static string ProbeRelease()
    {
        var token=CancellationToken.None;
        var release=LoadRelease(token);
        Version version;
        if(release==null || release.draft || release.prerelease || !TryVersion(release.tag_name,out version)) throw new InvalidDataException("发布版本错误。");
        string name="YY-Voice-Assistant-v"+version.ToString(3)+"-win-x64.zip";
        var asset=FindAsset(release,name); var checksum=FindAsset(release,name+".sha256");
        string hash=ParseHash(Encoding.ASCII.GetString(Download(checksum.browser_download_url,4096,token,null)),name);
        byte[] package=Download(asset.browser_download_url,128*1024*1024,token,null);
        if(package.LongLength!=asset.size) throw new InvalidDataException("文件大小错误。");
        string fixture=Path.Combine(Path.GetTempPath(),"YY-release-probe-"+Guid.NewGuid().ToString("N"));
        ValidateAndExtract(package,hash,version,fixture);
        return "PASS: Gitee latest stable release, assets, SHA256, download, executable version; no installation performed. Version="+version+"; Fixtures="+fixture;
    }

    internal static string SelfTest()
    {
        var report=new StringBuilder();
        Action<bool,string> check=delegate(bool success,string name) { if(!success) throw new Exception(name); report.AppendLine("PASS: "+name); };
        Version a,b;
        check(TryVersion("v0.1.10",out a) && TryVersion("0.1.9",out b) && a>b,"numeric version comparison");
        check(TryVersion("v"+VersionLabel,out a) && a==Current,"same version is current");
        check(!TryVersion("v0.2.0-beta",out a),"prerelease version rejected");
        var legacy=new JavaScriptSerializer().Deserialize<Preferences>("{\"Sound\":true}");
        check(legacy.AutoUpdate,"legacy settings default to automatic updates");
        bool rejected=false;
        try { FindAsset(new AppRelease { assets=new ReleaseAsset[0] },"missing.zip"); } catch(InvalidDataException) { rejected=true; }
        check(rejected,"missing asset rejected");
        rejected=false;
        try { FindAsset(new AppRelease { assets=new[]{new ReleaseAsset {name="test.zip",browser_download_url="https://example.com/test.zip"}} },"test.zip"); } catch(InvalidDataException) { rejected=true; }
        check(rejected,"foreign download source rejected");
        string sampleUrl="https://gitee.com/"+Repository+"/releases/download/v0.1.5/test.zip";
        var sample=new AppRelease {tag_name="v0.1.5",assets=new[]{new ReleaseAsset {name="test.zip",browser_download_url=sampleUrl}}};
        string json=new JavaScriptSerializer().Serialize(new[]{new ReleaseAsset {name="test.zip",browser_download_url=sampleUrl,size=123}});
        check(FindAsset(MergeAttachments(sample,json),"test.zip").size==123,"Gitee attachment sizes merged with release metadata");
        rejected=false;
        try { MergeAttachments(new AppRelease {assets=new ReleaseAsset[0]},json); } catch(InvalidDataException) { rejected=true; }
        check(rejected,"unlisted Gitee attachment rejected");
        foreach(string bad in new[]{sampleUrl.Replace("v0.1.5/","v0.1.4/"),sampleUrl+"?redirect=foreign",sampleUrl.Replace("gitee.com/","gitee.com.evil.example/")}) {
            rejected=false;
            try { FindAsset(new AppRelease {tag_name="v0.1.5",assets=new[]{new ReleaseAsset {name="test.zip",browser_download_url=bad}}},"test.zip"); } catch(InvalidDataException) { rejected=true; }
            check(rejected,"wrong release or untrusted Gitee URL rejected");
        }
        string fixture=Path.Combine(Path.GetTempPath(),"YY-update-test-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        string stage=Path.Combine(fixture,"stage"),target=Path.Combine(fixture,"target");
        Directory.CreateDirectory(target);
        byte[] package;
        using(var memory=new MemoryStream()) {
            using(var zip=new ZipArchive(memory,ZipArchiveMode.Create,true)) {
                foreach(string name in new[]{"YY语音助手.exe","开麦.wav","关麦.wav","使用说明.txt"}) {
                    using(var item=zip.CreateEntry(name).Open()) {
                        byte[] content=name.EndsWith(".exe") ? File.ReadAllBytes(Assembly.GetExecutingAssembly().Location) : Encoding.UTF8.GetBytes("fixture");
                        item.Write(content,0,content.Length);
                    }
                }
            }
            package=memory.ToArray();
        }
        string hash;
        using(var sha=SHA256.Create()) hash=BitConverter.ToString(sha.ComputeHash(package)).Replace("-","").ToLowerInvariant();
        check(ParseHash(hash+"  app.zip\n","app.zip")==hash,"checksum sidecar parsed");
        ValidateAndExtract(package,hash,Current,stage);
        check(File.Exists(Path.Combine(stage,"YY语音助手.exe")),"valid release extracted and executable version checked");
        rejected=false;
        try { ValidateAndExtract(package,new String('0',64),Current,Path.Combine(fixture,"corrupt")); } catch(InvalidDataException) { rejected=true; }
        check(rejected && !Directory.Exists(Path.Combine(fixture,"corrupt")),"corrupt download rejected before extraction");
        rejected=false;
        try { ValidateAndExtract(package,hash,new Version(99,0,0,0),Path.Combine(fixture,"mismatch")); } catch(InvalidDataException) { rejected=true; }
        check(rejected,"wrong executable version rejected");
        byte[] unsafeZip;
        using(var memory=new MemoryStream()) {
            using(var zip=new ZipArchive(memory,ZipArchiveMode.Create,true)) using(var item=zip.CreateEntry("../escape.txt").Open()) item.WriteByte(1);
            unsafeZip=memory.ToArray();
        }
        string unsafeHash;
        using(var sha=SHA256.Create()) unsafeHash=BitConverter.ToString(sha.ComputeHash(unsafeZip)).Replace("-","").ToLowerInvariant();
        rejected=false;
        try { ValidateAndExtract(unsafeZip,unsafeHash,Current,Path.Combine(fixture,"unsafe")); } catch(InvalidDataException) { rejected=true; }
        check(rejected && !File.Exists(Path.Combine(fixture,"escape.txt")),"ZIP path traversal and unexpected files rejected");
        foreach(string name in new[]{"YY语音助手.exe","设置.json","开麦.wav","关麦.wav"}) File.WriteAllText(Path.Combine(target,name),"original:"+name);
        Directory.CreateDirectory(Path.Combine(target,"自定义音效"));
        File.WriteAllText(Path.Combine(target,"自定义音效","mine.mp3"),"personal");
        InstallFiles(stage,target,delegate {});
        check(HashFile(Path.Combine(stage,"YY语音助手.exe"))==HashFile(Path.Combine(target,"YY语音助手.exe")),"executable replacement");
        check(File.ReadAllText(Path.Combine(target,"设置.json"))=="original:设置.json" && File.ReadAllText(Path.Combine(target,"开麦.wav"))=="original:开麦.wav" && File.ReadAllText(Path.Combine(target,"关麦.wav"))=="original:关麦.wav" && File.ReadAllText(Path.Combine(target,"自定义音效","mine.mp3"))=="personal","settings, both sounds and imported audio preserved");
        File.WriteAllText(Path.Combine(target,"YY语音助手.exe"),"rollback-fixture");
        rejected=false;
        try { InstallFiles(stage,target,delegate { throw new IOException("simulated launch failure"); }); } catch(IOException) { rejected=true; }
        check(rejected && File.ReadAllText(Path.Combine(target,"YY语音助手.exe"))=="rollback-fixture","launch failure restores previous executable");
        File.Delete(Path.Combine(target,"关麦.wav"));
        InstallFiles(stage,target,delegate {});
        check(File.ReadAllText(Path.Combine(target,"关麦.wav"))=="fixture","missing default sound supplied");
        report.AppendLine("Fixtures: "+fixture);
        return report.ToString();
    }
}
