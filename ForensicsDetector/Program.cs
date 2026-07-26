using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MetadataExtractor;
using OpenCvSharp;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;

namespace ForensicsDetector;

internal static class Program
{
    private static string _currentLang = "ru";
    private static string _botToken = "";
    
    private record ForensicModuleResult(Mat RenderMap, double MetricScore, bool HasAnomaly) : IDisposable
    {
        public void Dispose()
        {
            RenderMap?.Dispose();
        }
    }

    private record PipelineResult(
        string InputPath,
        string ReportPath,
        ForgeryResult ForgeryResult,
        AiAnalysisResult AiResult
    );

    private record PrnuResult(double NoiseEnergy, double FlatnessRatio, bool IsSyntheticPrnu);
    private record SnrResult(double SnrRatio, bool IsAiMismatch);
    private record AiAnalysisResult(int AiProbability, string Verdict, List<string> AiTriggers, bool IsMessengerImage);
    private record ForgeryResult(int Score, List<string> Triggers);
    private record MetadataResult(bool PicsArtDetected, List<string> DetectionReasons, Dictionary<string, Dictionary<string, string>> AllTags, bool IsExifStripped);
    private record LiquifyResult(double SuspiciousRatioPercent, string Assessment);

    static async Task Main(string[] args)
    {
        Console.Title = "Professional Photo Forensics & AI Suite";
        LoadConfig();

        if (args.Length > 0 && File.Exists(args[0]))
        {
            ProcessLocalImage(args[0]);
            return;
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("==================================================");
        Console.WriteLine(T(" Выберите режим работы / Choose Mode:", " Select Operation Mode:"));
        Console.WriteLine(" 1. Анализ локального файла (Console)");
        Console.WriteLine(" 2. Запустить Telegram Бота (Telegram Bot)");
        Console.WriteLine("==================================================");
        Console.Write(T("Выбор [1/2]: ", "Choice [1/2]: "));
        Console.ResetColor();

        var mode = Console.ReadLine()?.Trim() ?? "1";

        if (mode == "2")
        {
            if (string.IsNullOrWhiteSpace(_botToken))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(T("Введите Telegram Bot Token: ", "Enter Telegram Bot Token (from @BotFather): "));
                Console.ResetColor();
                _botToken = Console.ReadLine()?.Trim() ?? "";
                SaveConfig();
            }

            if (!string.IsNullOrWhiteSpace(_botToken))
            {
                await StartTelegramBotAsync(_botToken);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(T("Токен не указан. Запуск отменен.", "Token not provided. Aborting."));
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write(T("Введите полный путь к изображению (.jpg, .png, .webp): ", 
                            "Enter full path to image (.jpg, .png, .webp): "));
            Console.ResetColor();
            var inputPath = Console.ReadLine()?.Trim('"') ?? "";
            
            if (File.Exists(inputPath))
            {
                ProcessLocalImage(inputPath);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(T("Ошибка: Указанный файл не существует.", "Error: The specified file does not exist."));
                Console.ResetColor();
            }
        }

        Console.WriteLine("\n" + T("Нажмите Enter для выхода из программы...", "Press Enter to exit..."));
        Console.ReadLine();
    }

    private static string GetOverallVerdict(int forgeryScore, int aiProbability) => (forgeryScore, aiProbability) switch
    {
        _ when aiProbability >= 65 && forgeryScore >= 40 => T("🚨 Гибридная подделка (ИИ-генерация + Фотомонтаж)", "🚨 Hybrid Forgery (AI Generation + Collage)"),
        _ when forgeryScore >= 45 => T("⚠️ Обнаружен фотомонтаж / Вклейка / Глубокая редактура", "⚠️ Photo Manipulation / Splicing / Heavy Edit Detected"),
        _ when aiProbability >= 65 => T("🤖 ИИ-генерация / Синтетический арт", "🤖 AI Generation / Synthetic Art"),
        _ when forgeryScore >= 25 => T("🔍 Обнаружены следы локальной правки / Вклейки", "🔍 Local Edit / Splicing Signs Detected"),
        _ when aiProbability >= 40 => T("🎨 Высокая вероятность ИИ / Генеративных фильтров", "🎨 High AI / Generative Filter Probability"),
        _ when aiProbability >= 25 => T("🔍 Сомнительный снимок (Признаки обработок)", "🔍 Suspicious Image (Signs of processing)"),
        _ => T("✅ Естественный снимок (Без следов монтажа и ИИ)", "✅ Natural Photo (No Manipulation or AI detected)")
    };

    private static PipelineResult RunPipeline(string inputPath)
    {
        Console.WriteLine(T("\n[1/16] Анализ EXIF, XMP и сигнатур ПО...", "\n[1/16] Analyzing EXIF, XMP and software signatures..."));
        var metaResult = AnalyzeMetadata(inputPath);

        Console.WriteLine(T("[2/16] Проверка криптографических ИИ-подписей (C2PA)...", "[2/16] Checking cryptographic AI signatures (C2PA)..."));
        bool hasC2Pa = AnalyzeC2PaMetadata(inputPath);

        Console.WriteLine(T("[3/16] Детекция 'Редакции' и локального размытия...", "[3/16] Detecting 'Editing' and local blur..."));
        var liquifyResult = AnalyzeLiquifyArtifacts(inputPath);

        Console.WriteLine(T("[4/16] Двойное квантование JPEG (DQ Analysis)...", "[4/16] Double JPEG Compression (DQ Analysis)..."));
        bool isDoubleJpeg = AnalyzeDoubleJpegCompression(inputPath);

        Console.WriteLine(T("[5/16] Генерация классической карты ELA и локальный анализ пиков...", "[5/16] Generating ELA map & Local Peak Analysis..."));
        using var elaImage = GenerateElaMap(inputPath, out double elaScore, out double elaMaxDiff, quality: 95, scale: 20);

        Console.WriteLine(T("[6/16] Извлечение шума сенсора и локальный расчет дисперсии (High-Pass Noise)...", "[6/16] Extracting sensor noise map & variance calculation..."));
        using var noiseResult = AnalyzeHighPassNoise(inputPath);

        Console.WriteLine(T("[7/16] Интеллектуальная детекция 'Штампа' (Векторная кластеризация)...", "[7/16] Intelligent Clone Detection (Vector Clustering)..."));
        using var copyMoveResult = DetectCopyMove(inputPath, out int cloneCount);

        Console.WriteLine(T("[8/16] Расчет призраков сжатия JPEG Ghosts (Q75 & Q85)...", "[8/16] Calculating JPEG Ghosts (Q75 & Q85)..."));
        using var ghost75Result = CalculateJpegGhost(inputPath, 75);
        using var ghost85Result = CalculateJpegGhost(inputPath, 85);

        Console.WriteLine(T("[9/16] Анализ локального несоответствия шума (Noise Mismatch)...", "[9/16] Analyzing noise mismatch..."));
        double noiseInconsistency = AnalyzeNoiseMismatch(inputPath, out _);

        Console.WriteLine(T("[10/16] Частотный анализ Фурье (2D FFT Spectrum)...", "[10/16] Performing 2D FFT Spectral Analysis..."));
        using var fftResult = AnalyzeFftSpectrum(inputPath);

        Console.WriteLine(T("[11/16] Анализ структуры демозаики матрицы (Bayer CFA)...", "[11/16] Analyzing Bayer CFA Demosaicing..."));
        using var bayerResult = AnalyzeBayerCfa(inputPath);

        Console.WriteLine(T("[12/16] PRNU (Photo-Response Non-Uniformity) Анализ...", "[12/16] PRNU Sensor Fingerprint Analysis..."));
        var prnuResult = AnalyzePrnuFingerprint(inputPath);

        Console.WriteLine(T("[13/16] Chrominance vs Luminance SNR Mismatch (Y/CbCr)...", "[13/16] Chrominance vs Luminance SNR Mismatch..."));
        var snrResult = AnalyzeChrominanceSnr(inputPath);

        Console.WriteLine(T("[14/16] SRM (Spatial Rich Models) Residuals 3-го порядка...", "[14/16] SRM 3rd-Order Residual Analysis..."));
        double srmScore = AnalyzeSrmResiduals(inputPath);

        Console.WriteLine(T("[15/16] Проверка хроматических аберраций (CA Analysis)...", "[15/16] Checking Chromatic Aberrations (CA Analysis)..."));
        bool hasCaAnomaly = AnalyzeChromaticAberration(inputPath);

        Console.WriteLine(T("[16/16] Поиск артефактов апскейла (Checkerboard)...", "[16/16] Searching for upscaler artifacts (Checkerboard)..."));
        double checkerboardScore = AnalyzeUpscalerCheckerboard(inputPath);

        var forgeryResult = AnalyzeForgery(
            metaResult, 
            liquifyResult, 
            cloneCount, 
            noiseInconsistency, 
            elaScore,
            elaMaxDiff,
            isDoubleJpeg,
            srmScore,
            bayerResult.MetricScore,
            noiseResult.MetricScore,
            ghost75Result.MetricScore,
            ghost85Result.MetricScore
        );

        var aiResult = AnalyzeAiHeuristic(
            fftResult.MetricScore, 
            bayerResult.MetricScore, 
            metaResult.IsExifStripped, 
            prnuResult,
            snrResult,
            srmScore,
            hasC2Pa,
            hasCaAnomaly,
            checkerboardScore,
            forgeryResult.Score
        );

        string reportPath = GenerateHtmlReport(
            inputPath, metaResult, liquifyResult, elaImage, noiseResult, copyMoveResult, ghost75Result, ghost85Result, fftResult, bayerResult, 
            forgeryResult, aiResult, prnuResult, snrResult, srmScore, hasC2Pa, isDoubleJpeg, hasCaAnomaly, checkerboardScore
        );

        return new PipelineResult(inputPath, reportPath, forgeryResult, aiResult);
    }

    private static void ProcessLocalImage(string inputPath)
    {
        try
        {
            var res = RunPipeline(inputPath);
            string overallVerdict = GetOverallVerdict(res.ForgeryResult.Score, res.AiResult.AiProbability);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(T("\n✓ Анализ успешно завершен!", "\n✓ Analysis completed successfully!"));
            
            Console.ForegroundColor = res.ForgeryResult.Score > 40 ? ConsoleColor.Red : (res.ForgeryResult.Score > 20 ? ConsoleColor.Yellow : ConsoleColor.Green);
            Console.WriteLine($"{T("Шанс фотошопа / редакции", "Photoshop / Manipulation Probability")}: {res.ForgeryResult.Score}%");
            foreach (var tr in res.ForgeryResult.Triggers)
                Console.WriteLine($"  └─ {tr}");

            Console.ForegroundColor = res.AiResult.AiProbability > 50 ? ConsoleColor.Magenta : (res.AiResult.AiProbability > 25 ? ConsoleColor.Yellow : ConsoleColor.Cyan);
            Console.WriteLine($"{T("Вероятность ИИ / Digital Art", "AI / CGI Probability")}: {res.AiResult.AiProbability}% ({res.AiResult.Verdict})");
            foreach (var tr in res.AiResult.AiTriggers)
                Console.WriteLine($"  └─ {tr}");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"\n📌 {T("Итоговый вердикт", "Overall Verdict")}: {overallVerdict}\n");

            Console.ResetColor();
            Console.WriteLine($"{T("Отчет сохранен", "Report saved at")}: {res.ReportPath}");
            OpenInBrowser(res.ReportPath);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n{T("Критическая ошибка выполнения", "Critical execution error")}: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            Console.ResetColor();
        }
    }

    private static async Task StartTelegramBotAsync(string token)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        string apiUrl = $"https://api.telegram.org/bot{token}/";

        try
        {
            var meRes = await client.GetStringAsync(apiUrl + "getMe");
            using var meDoc = JsonDocument.Parse(meRes);
            string botName = meDoc.RootElement.GetProperty("result").GetProperty("username").GetString() ?? "Bot";
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[Telegram Bot] Успешно запущен: @{botName}");
            Console.WriteLine("[Telegram Bot] Ожидание изображений в чатах... (Нажмите Ctrl+C для остановки)");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[Telegram Bot] Ошибка подключения. Проверьте токен: {ex.Message}");
            Console.ResetColor();
            return;
        }

        long offset = 0;

        while (true)
        {
            try
            {
                string jsonRes = await client.GetStringAsync($"{apiUrl}getUpdates?offset={offset}&timeout=20");
                using var doc = JsonDocument.Parse(jsonRes);

                foreach (var update in doc.RootElement.GetProperty("result").EnumerateArray())
                {
                    offset = update.GetProperty("update_id").GetInt64() + 1;

                    if (!update.TryGetProperty("message", out var message)) continue;

                    long chatId = message.GetProperty("chat").GetProperty("id").GetInt64();
                    string fileId = "";
                    string fileName = "image.jpg";

                    if (message.TryGetProperty("photo", out var photoArray) && photoArray.GetArrayLength() > 0)
                    {
                        var largestPhoto = photoArray.EnumerateArray().Last();
                        fileId = largestPhoto.GetProperty("file_id").GetString() ?? "";
                    }
                    else if (message.TryGetProperty("document", out var docObj))
                    {
                        string mime = docObj.TryGetProperty("mime_type", out var m) ? m.GetString() ?? "" : "";
                        if (mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase) || 
                            mime.Contains("jpg", StringComparison.OrdinalIgnoreCase) || 
                            mime.Contains("png", StringComparison.OrdinalIgnoreCase) || 
                            mime.Contains("webp", StringComparison.OrdinalIgnoreCase))
                        {
                            fileId = docObj.GetProperty("file_id").GetString() ?? "";
                            if (docObj.TryGetProperty("file_name", out var fn))
                                fileName = fn.GetString() ?? "image.jpg";
                        }
                    }

                    if (!string.IsNullOrEmpty(fileId))
                    {
                        _ = Task.Run(() => HandleBotImageAsync(client, token, chatId, fileId, fileName));
                    }
                    else if (message.TryGetProperty("text", out var textObj) && textObj.GetString() == "/start")
                    {
                        string welcome = "👋 <b>Привет! Я бот форензик-анализа и детекции ИИ.</b>\n\n" +
                                        "Отправь мне любую картинку, и я проведу глубокий анализ.\n\n" +
                                        "⚠️ <b>ВАЖНО:</b> Если ты отправишь картинку как «Фото», Telegram удалит все EXIF данные (защита приватности). Чтобы проверить метаданные камеры, отправляй картинки как <b>Файл / Документ (Скрепка 📎 -> Файл)</b>.";
                        await TgSendMessageAsync(client, token, chatId, welcome);
                    }
                }
            }
            catch (TaskCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[Telegram Bot Error] {ex.Message}");
                await Task.Delay(3000);
            }
        }
    }

    private static async Task HandleBotImageAsync(HttpClient client, string token, long chatId, string fileId, string fileName)
    {
        string tempInput = Path.Combine(Path.GetTempPath(), $"tg_{Guid.NewGuid()}_{fileName}");
        try
        {
            await TgSendMessageAsync(client, token, chatId, "⏳ <b>Получено изображение!</b>\nЗапущен полный форензик-анализ (16 этапов)...");

            string infoRes = await client.GetStringAsync($"https://api.telegram.org/bot{token}/getFile?file_id={fileId}");
            using var infoDoc = JsonDocument.Parse(infoRes);
            string filePathOnServer = infoDoc.RootElement.GetProperty("result").GetProperty("file_path").GetString() ?? "";

            byte[] fileData = await client.GetByteArrayAsync($"https://api.telegram.org/file/bot{token}/{filePathOnServer}");
            await File.WriteAllBytesAsync(tempInput, fileData);

            var res = RunPipeline(tempInput);
            string overallVerdict = GetOverallVerdict(res.ForgeryResult.Score, res.AiResult.AiProbability);

            var sb = new StringBuilder();
            sb.AppendLine("<b>🛡️ Результаты форензик анализа</b>\n");
            sb.AppendLine($"📊 <b>Фотошоп / Редакция:</b> {res.ForgeryResult.Score}%");
            sb.AppendLine($"🤖 <b>Вероятность ИИ:</b> {res.AiResult.AiProbability}%");
            sb.AppendLine($"📌 <b>Вердикт:</b> {overallVerdict}\n");

            if (res.ForgeryResult.Triggers.Count > 0)
            {
                sb.AppendLine("<b>⚠️ Признаки редактирования:</b>");
                foreach (var tr in res.ForgeryResult.Triggers)
                    sb.AppendLine($"• {tr}");
                sb.AppendLine();
            }

            if (res.AiResult.AiTriggers.Count > 0)
            {
                sb.AppendLine("<b>🧬 Признаки ИИ / Синтетики:</b>");
                foreach (var tr in res.AiResult.AiTriggers)
                    sb.AppendLine($"• {tr}");
                sb.AppendLine();
            }

            sb.AppendLine("📄 <i>Подробный интерактивный HTML-отчет со спектрограммами прикреплен ниже.</i>");

            await TgSendMessageAsync(client, token, chatId, sb.ToString());
            await TgSendDocumentAsync(client, token, chatId, res.ReportPath, "Forensics_Report.html");

            try { File.Delete(res.ReportPath); } catch { }
        }
        catch (Exception ex)
        {
            await TgSendMessageAsync(client, token, chatId, $"❌ <b>Ошибка анализа:</b> {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tempInput)) File.Delete(tempInput); } catch { }
        }
    }

    private static async Task TgSendMessageAsync(HttpClient client, string token, long chatId, string htmlText)
    {
        var payload = new { chat_id = chatId, text = htmlText, parse_mode = "HTML" };
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        await client.PostAsync($"https://api.telegram.org/bot{token}/sendMessage", content);
    }

    private static async Task TgSendDocumentAsync(HttpClient client, string token, long chatId, string filePath, string sendFileName)
    {
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent(chatId.ToString()), "chat_id");
        
        await using var fileStream = File.OpenRead(filePath);
        using var streamContent = new StreamContent(fileStream);
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("text/html");
        streamContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
        {
            Name = "\"document\"",
            FileName = $"\"{sendFileName}\""
        };

        form.Add(streamContent);
        await client.PostAsync($"https://api.telegram.org/bot{token}/sendDocument", form);
    }

    private static string GetConfigPath() => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");

    private static void LoadConfig()
    {
        string cfgPath = GetConfigPath();
        if (!File.Exists(cfgPath))
        {
            _currentLang = SelectLanguagePrompt();
            SaveConfig();
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(cfgPath));
            if (doc.RootElement.TryGetProperty("Language", out var langProp))
                _currentLang = langProp.GetString()?.ToLower() ?? "ru";
            if (doc.RootElement.TryGetProperty("TelegramBotToken", out var tokenProp))
                _botToken = tokenProp.GetString() ?? "";
        }
        catch { }
    }

    private static void SaveConfig()
    {
        try
        {
            var json = JsonSerializer.Serialize(new 
            { 
                Language = _currentLang,
                TelegramBotToken = _botToken 
            }, new JsonSerializerOptions { WriteIndented = true });
            
            File.WriteAllText(GetConfigPath(), json);
        }
        catch { }
    }

    private static string SelectLanguagePrompt()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("Select Language / Выберите язык:");
        Console.WriteLine("1. Русский (RU)");
        Console.WriteLine("2. English (EN)");
        Console.Write("Option / Выбор [1/2]: ");
        Console.ResetColor();

        string choice = Console.ReadLine()?.Trim() ?? "1";
        return (choice == "2" || choice.Equals("en", StringComparison.OrdinalIgnoreCase)) ? "en" : "ru";
    }

    private static string T(string ru, string en) => _currentLang == "en" ? en : ru;

    private static bool AnalyzeC2PaMetadata(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length == 0) return false;

            int bytesToRead = (int)Math.Min(fileInfo.Length, 1024 * 1024);
            byte[] buffer = new byte[bytesToRead];

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fs.ReadExactly(buffer, 0, bytesToRead);
            }

            string data = Encoding.ASCII.GetString(buffer);
            return data.Contains("c2pa", StringComparison.Ordinal) || data.Contains("jumb", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static bool AnalyzeDoubleJpegCompression(string filePath)
    {
        try
        {
            if (!filePath.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) && !filePath.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase))
                return false;

            using var src = Cv2.ImRead(filePath, ImreadModes.Grayscale);
            if (src.Empty()) return false;

            int w = src.Cols & -8; 
            int h = src.Rows & -8;
            if (w == 0 || h == 0) return false;

            using var cropped = new Mat(src, new Rect(0, 0, w, h));
            cropped.ConvertTo(cropped, MatType.CV_32F);

            var histogram = new int[2000];
            const int offset = 1000;

            for (int y = 0; y < h; y += 8)
            {
                for (int x = 0; x < w; x += 8)
                {
                    using var block = new Mat(cropped, new Rect(x, y, 8, 8));
                    using var dct = new Mat();
                    Cv2.Dct(block, dct);
                    int val = (int)Math.Round(dct.At<float>(1, 1)) + offset;
                    if ((uint)val < 2000) histogram[val]++;
                }
            }

            int combEffects = 0;
            for (int i = offset - 30; i < offset + 30; i++)
            {
                if (histogram[i] == 0 && histogram[i - 1] > 5 && histogram[i + 1] > 5) 
                    combEffects++;
            }
            return combEffects >= 4; 
        }
        catch { return false; }
    }

    private static bool AnalyzeChromaticAberration(string filePath)
    {
        try
        {
            using var src = Cv2.ImRead(filePath, ImreadModes.Color);
            if (src.Empty()) return false;

            int size = Math.Min(256, Math.Min(src.Cols / 4, src.Rows / 4));
            if (size < 64) return false;

            Cv2.Split(src, out Mat[] channels);
            using var b = channels[0]; 
            using var g = channels[1]; 
            using var r = channels[2];

            using var tlG = new Mat(g, new Rect(0, 0, size, size));
            using var tlR = new Mat(r, new Rect(0, 0, size, size));
            tlG.ConvertTo(tlG, MatType.CV_32F); 
            tlR.ConvertTo(tlR, MatType.CV_32F);

            Point2d shift = Cv2.PhaseCorrelate(tlG, tlR, null, out _);
            return Math.Abs(shift.X) < 0.05 && Math.Abs(shift.Y) < 0.05;
        }
        catch { return false; }
    }

    private static double AnalyzeUpscalerCheckerboard(string filePath)
    {
        try
        {
            using var src = Cv2.ImRead(filePath, ImreadModes.Grayscale);
            if (src.Empty()) return 0;

            using var laplacian = new Mat();
            Cv2.Laplacian(src, laplacian, MatType.CV_32F, ksize: 1);
            
            Cv2.MeanStdDev(laplacian, out _, out Scalar stddev);
            return Math.Round(stddev.Val0, 2);
        }
        catch { return 0; }
    }

    private static PrnuResult AnalyzePrnuFingerprint(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return new PrnuResult(0, 0, false);

        using var floatImg = new Mat();
        src.ConvertTo(floatImg, MatType.CV_32F);
        using var localMean = new Mat();
        Cv2.Blur(floatImg, localMean, new OpenCvSharp.Size(3, 3));
        using var prnuNoise = new Mat();
        Cv2.Absdiff(floatImg, localMean, prnuNoise);
        Cv2.MeanStdDev(prnuNoise, out Scalar meanNoise, out Scalar stdNoise);

        double energy = stdNoise.Val0;
        double flatnessRatio = energy / (meanNoise.Val0 + 1e-5);
        bool isSynthetic = energy < 0.40 || flatnessRatio < 0.28;

        return new PrnuResult(Math.Round(energy, 3), Math.Round(flatnessRatio, 3), isSynthetic);
    }

    private static SnrResult AnalyzeChrominanceSnr(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Color);
        if (src.Empty()) return new SnrResult(0, false);

        using var ycrcb = new Mat();
        Cv2.CvtColor(src, ycrcb, ColorConversionCodes.BGR2YCrCb);
        Cv2.Split(ycrcb, out Mat[] channels);

        double noiseY = GetChannelNoiseLevel(channels[0]);
        double noiseCr = GetChannelNoiseLevel(channels[1]);
        double noiseCb = GetChannelNoiseLevel(channels[2]);

        channels[0].Dispose(); 
        channels[1].Dispose(); 
        channels[2].Dispose();

        double noiseCbCr = Math.Max(0.0001, (noiseCr + noiseCb) / 2.0);
        double snrRatio = noiseY / noiseCbCr;
        bool isMismatch = snrRatio > 16.0 || snrRatio < 0.25;

        return new SnrResult(Math.Round(snrRatio, 2), isMismatch);
    }

    private static double GetChannelNoiseLevel(Mat channel)
    {
        using var blur = new Mat();
        Cv2.MedianBlur(channel, blur, 3);
        using var diff = new Mat();
        Cv2.Absdiff(channel, blur, diff);
        Cv2.MeanStdDev(diff, out _, out Scalar stddev);
        return stddev.Val0;
    }

    private static double AnalyzeSrmResiduals(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return 0;
        
        using var floatImg = new Mat();
        src.ConvertTo(floatImg, MatType.CV_32F);

        float[] kernel3RdData = [-1, 3, -3, 1];
        using var kernelH = Mat.FromPixelData(1, 4, MatType.CV_32FC1, kernel3RdData);
        using var resH = new Mat();
        Cv2.Filter2D(floatImg, resH, MatType.CV_32F, kernelH);
        using var absRes = new Mat();
        Cv2.Absdiff(resH, Scalar.All(0), absRes);

        Cv2.MeanStdDev(absRes, out Scalar meanRes, out Scalar stdRes);
        double anomalyScore = (stdRes.Val0 / (meanRes.Val0 + 0.0001)) * 5.0;
        return Math.Round(anomalyScore, 2);
    }

    private static ForensicModuleResult AnalyzeHighPassNoise(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return new ForensicModuleResult(new Mat(), 0, false);

        using var blurred = new Mat();
        Cv2.GaussianBlur(src, blurred, new OpenCvSharp.Size(5, 5), 0);
        using var highPass = new Mat();
        Cv2.Absdiff(src, blurred, highPass);

        var noiseMap = new Mat();
        Cv2.EqualizeHist(highPass, noiseMap);

        Cv2.MeanStdDev(highPass, out Scalar mean, out Scalar _);

        const int gridSize = 4;
        int cellW = highPass.Cols / gridSize;
        int cellH = highPass.Rows / gridSize;
        var cellStds = new List<double>();

        for (int x = 0; x < gridSize; x++)
        {
            for (int y = 0; y < gridSize; y++)
            {
                using var cell = new Mat(highPass, new Rect(x * cellW, y * cellH, cellW, cellH));
                Cv2.MeanStdDev(cell, out _, out Scalar cellStd);
                cellStds.Add(cellStd.Val0);
            }
        }

        double maxStd = cellStds.Count > 0 ? cellStds.Max() : 0;
        double minStd = cellStds.Count > 0 ? cellStds.Min() : 0;
        double stdInconsistency = (maxStd - minStd) / (mean.Val0 + 0.001) * 10.0;

        double score = Math.Clamp(stdInconsistency, 0, 100);
        return new ForensicModuleResult(noiseMap, Math.Round(score, 2), score > 35.0);
    }

    private static ForensicModuleResult CalculateJpegGhost(string inputPath, int targetQuality)
    {
        using var original = Cv2.ImRead(inputPath, ImreadModes.Color);
        if (original.Empty()) return new ForensicModuleResult(new Mat(), 0, false);

        Cv2.ImEncode(".jpg", original, out byte[] buf, [new ImageEncodingParam(ImwriteFlags.JpegQuality, targetQuality)]);
        using var resaved = Cv2.ImDecode(buf, ImreadModes.Color);

        using var diff = new Mat();
        Cv2.Absdiff(original, resaved, diff);
        using var grayDiff = new Mat();
        Cv2.CvtColor(diff, grayDiff, ColorConversionCodes.BGR2GRAY);

        var ghostMap = new Mat();
        Cv2.Normalize(grayDiff, ghostMap, 0, 255, NormTypes.MinMax);

        Cv2.MeanStdDev(grayDiff, out Scalar mean, out Scalar stdDev);
        double ghostScore = Math.Clamp((stdDev.Val0 / (mean.Val0 + 0.001)) * 12.0, 0, 100);

        return new ForensicModuleResult(ghostMap, Math.Round(ghostScore, 2), ghostScore > 40.0);
    }

    private static ForensicModuleResult AnalyzeFftSpectrum(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return new ForensicModuleResult(new Mat(), 0, false);

        int m = Cv2.GetOptimalDFTSize(src.Rows);
        int n = Cv2.GetOptimalDFTSize(src.Cols);

        using var padded = new Mat();
        Cv2.CopyMakeBorder(src, padded, 0, m - src.Rows, 0, n - src.Cols, BorderTypes.Constant, Scalar.All(0));
        padded.ConvertTo(padded, MatType.CV_32F);

        using var dft = new Mat();
        Cv2.Dft(padded, dft, DftFlags.ComplexOutput);

        Cv2.Split(dft, out Mat[] planes);
        using var magnitude = new Mat();
        Cv2.Magnitude(planes[0], planes[1], magnitude);

        planes[0].Dispose(); 
        planes[1].Dispose();

        Cv2.Add(magnitude, Scalar.All(1), magnitude);
        Cv2.Log(magnitude, magnitude);

        Cv2.MeanStdDev(magnitude, out Scalar mean, out Scalar stddev);
        double fftScore = Math.Round((stddev.Val0 / (mean.Val0 + 0.0001)) * 10.0, 2);

        using var magCropped = new Mat(magnitude, new Rect(0, 0, magnitude.Cols & -2, magnitude.Rows & -2));

        int cx = magCropped.Cols / 2;
        int cy = magCropped.Rows / 2;

        using var q0 = new Mat(magCropped, new Rect(0, 0, cx, cy));
        using var q1 = new Mat(magCropped, new Rect(cx, 0, cx, cy));
        using var q2 = new Mat(magCropped, new Rect(0, cy, cx, cy));
        using var q3 = new Mat(magCropped, new Rect(cx, cy, cx, cy));

        using var tmp = new Mat();
        q0.CopyTo(tmp); q3.CopyTo(q0); tmp.CopyTo(q3);
        q1.CopyTo(tmp); q2.CopyTo(q1); tmp.CopyTo(q2);

        using var normalized = new Mat();
        Cv2.Normalize(magCropped, normalized, 0, 255, NormTypes.MinMax);
        var result = new Mat();
        normalized.ConvertTo(result, MatType.CV_8U);

        return new ForensicModuleResult(result, fftScore, fftScore > 6.0);
    }

    private static ForensicModuleResult AnalyzeBayerCfa(string inputPath)
    {
        using var src = Cv2.ImRead(inputPath, ImreadModes.Color);
        if (src.Empty()) return new ForensicModuleResult(new Mat(), 0, false);

        Cv2.Split(src, out Mat[] channels);
        using var gChannel = channels[1];
        channels[0].Dispose(); 
        channels[2].Dispose();

        float[] kernelData = [
            0,  1, 0,
            1, -4, 1,
            0,  1, 0
        ];
        using var kernel = Mat.FromPixelData(3, 3, MatType.CV_32FC1, kernelData);
        using var floatG = new Mat();
        gChannel.ConvertTo(floatG, MatType.CV_32F);

        using var filtered = new Mat();
        Cv2.Filter2D(floatG, filtered, MatType.CV_32F, kernel);
        using var absFiltered = new Mat();
        Cv2.Absdiff(filtered, Scalar.All(0), absFiltered);

        const int blockSize = 16;
        int blocksX = absFiltered.Cols / blockSize;
        int blocksY = absFiltered.Rows / blockSize;

        if (blocksX < 2 || blocksY < 2) return new ForensicModuleResult(new Mat(), 0, false);

        var blockInconsistencies = new List<double>();

        for (int bx = 0; bx < blocksX; bx++)
        {
            for (int by = 0; by < blocksY; by++)
            {
                using var block = new Mat(absFiltered, new Rect(bx * blockSize, by * blockSize, blockSize, blockSize));

                double sumEven = 0, sumOdd = 0;
                int countEven = 0, countOdd = 0;

                for (int r = 0; r < blockSize; r++)
                {
                    for (int c = 0; c < blockSize; c++)
                    {
                        float val = block.At<float>(r, c);
                        if ((r + c) % 2 == 0) { sumEven += val; countEven++; }
                        else { sumOdd += val; countOdd++; }
                    }
                }

                double avgEven = countEven > 0 ? sumEven / countEven : 0;
                double avgOdd = countOdd > 0 ? sumOdd / countOdd : 0;
                double mean = (avgEven + avgOdd) / 2.0;

                if (mean > 0.5)
                {
                    blockInconsistencies.Add(Math.Abs(avgEven - avgOdd) / mean);
                }
            }
        }

        double anomalyScore = 0;
        if (blockInconsistencies.Count > 5)
        {
            double avg = blockInconsistencies.Average();
            double variance = blockInconsistencies.Sum(d => Math.Pow(d - avg, 2)) / blockInconsistencies.Count;
            anomalyScore = Math.Round(Math.Sqrt(variance) * 100.0, 2);
        }

        var bayerMap = new Mat();
        Cv2.Normalize(absFiltered, bayerMap, 0, 255, NormTypes.MinMax);
        bayerMap.ConvertTo(bayerMap, MatType.CV_8U);

        return new ForensicModuleResult(bayerMap, anomalyScore, anomalyScore > 15.0);
    }

    private static ForensicModuleResult DetectCopyMove(string inputPath, out int cloneClustersCount)
    {
        cloneClustersCount = 0;
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return new ForensicModuleResult(new Mat(), 0, false);

        var resultImage = Cv2.ImRead(inputPath, ImreadModes.Color);

        using var orb = ORB.Create(nFeatures: 6000, scoreType: ORBScoreType.Harris);
        using var descriptors = new Mat();
        orb.DetectAndCompute(src, null, out KeyPoint[] keypoints, descriptors);

        if (descriptors.Empty() || descriptors.Rows < 2) 
            return new ForensicModuleResult(resultImage, 0, false);

        using var matcher = new BFMatcher(NormTypes.Hamming);
        var knnMatches = matcher.KnnMatch(descriptors, descriptors, k: 3);

        var validMatches = new List<(Point2f pt1, Point2f pt2, double dx, double dy)>();

        foreach (var matchGroup in knnMatches)
        {
            if (matchGroup.Length < 2) continue;
            var match = matchGroup[1];
            if (match.Distance <= 18)
            {
                var pt1 = keypoints[match.QueryIdx].Pt;
                var pt2 = keypoints[match.TrainIdx].Pt;

                double dist = Math.Sqrt(Math.Pow(pt1.X - pt2.X, 2) + Math.Pow(pt1.Y - pt2.Y, 2));
                if (dist > 50.0)
                {
                    validMatches.Add((pt1, pt2, pt1.X - pt2.X, pt1.Y - pt2.Y));
                }
            }
        }

        var used = new bool[validMatches.Count];
        for (int i = 0; i < validMatches.Count; i++)
        {
            if (used[i]) continue;
            var cluster = new List<int> { i };

            for (int j = i + 1; j < validMatches.Count; j++)
            {
                if (used[j]) continue;
                if (Math.Abs(validMatches[i].dx - validMatches[j].dx) < 12 &&
                    Math.Abs(validMatches[i].dy - validMatches[j].dy) < 12)
                {
                    cluster.Add(j);
                }
            }

            if (cluster.Count >= 8)
            {
                cloneClustersCount++;
                foreach (var idx in cluster)
                {
                    used[idx] = true;
                    Cv2.Line(resultImage, validMatches[idx].pt1.ToPoint(), validMatches[idx].pt2.ToPoint(), Scalar.Red, 2);
                    Cv2.Circle(resultImage, validMatches[idx].pt1.ToPoint(), 3, Scalar.Yellow, -1);
                    Cv2.Circle(resultImage, validMatches[idx].pt2.ToPoint(), 3, Scalar.Red, -1);
                }
            }
        }

        double score = Math.Min(100, cloneClustersCount * 25.0);
        return new ForensicModuleResult(resultImage, score, cloneClustersCount > 0);
    }

    private static AiAnalysisResult AnalyzeAiHeuristic(
        double fftScore, 
        double bayerScore, 
        bool isExifStripped, 
        PrnuResult prnu,
        SnrResult snr,
        double srmScore,
        bool hasC2Pa,
        bool hasCaAnomaly,
        double checkerboardScore,
        int forgeryScore)
    {
        var triggers = new List<string>();
        double baseScore = 0;
        
        int hardIndicators = 0; 
        int missingPhysics = 0;   

        bool hasPhysicsAnomalies = snr.IsAiMismatch || srmScore > 12.0 || fftScore > 6.0;
        bool isMessengerImage = isExifStripped && !prnu.IsSyntheticPrnu && !hasPhysicsAnomalies;

        if (hasC2Pa)
        {
            baseScore += 100;
            hardIndicators += 3;
            triggers.Add(T("Обнаружены C2PA Content Credentials (100% ИИ генерация / ИИ фильтр)", 
                           "C2PA Content Credentials detected (100% AI generation / AI filter)"));
        }

        if (srmScore > 12.0)
        {
            if (forgeryScore < 30)
            {
                baseScore += 20;
                hardIndicators++;
                triggers.Add(T($"Аномалия SRM-остатков 3-го порядка ({srmScore})", $"SRM 3rd-order residual anomaly ({srmScore})"));
            }
        }
        if (snr.IsAiMismatch)
        {
            if (forgeryScore < 30)
            {
                baseScore += 20;
                hardIndicators++;
                triggers.Add(T($"Дисбаланс шума яркости и цвета Y/CbCr SNR ({snr.SnrRatio})", $"Chrominance/Luminance SNR mismatch ({snr.SnrRatio})"));
            }
        }
        if (fftScore > 6.0)
        {
            if (forgeryScore < 30)
            {
                baseScore += 25;
                hardIndicators++;
                triggers.Add(T($"Спектральная аномалия 2D FFT ({fftScore})", $"2D FFT spectral anomaly ({fftScore})"));
            }
        }
        if (hasCaAnomaly)
        {
            baseScore += 15;
            hardIndicators++;
            triggers.Add(T("Отсутствие радиальных хроматических аберраций (Синтетическая линза)", "Missing radial chromatic aberrations (Synthetic lens)"));
        }
        if (checkerboardScore > 24.0)
        {
            baseScore += 20;
            hardIndicators++;
            triggers.Add(T($"Сетка апскейлера (Checkerboard variance: {checkerboardScore})", $"Upscaler checkerboard artifacts (variance: {checkerboardScore})"));
        }

        if (prnu.IsSyntheticPrnu)
        {
            baseScore += 10;
            missingPhysics++;
            triggers.Add(T("Стерильный PRNU-отпечаток (отсутствует матрица)", "Sterile PRNU sensor fingerprint"));
        }
        if (!isMessengerImage && bayerScore < 5.0)
        {
            if (forgeryScore < 30)
            {
                baseScore += 10;
                missingPhysics++;
                triggers.Add(T($"Нарушение интерполяции сенсора (Bayer CFA: {bayerScore})", $"Missing Bayer CFA interpolation structure"));
            }
        }
        if (isExifStripped && hasPhysicsAnomalies && forgeryScore < 30)
        {
            baseScore += 10;
            triggers.Add(T("Отсутствие EXIF на фоне физических аномалий", "Missing EXIF combined with physical anomalies"));
        }

        if (hardIndicators >= 2)
        {
            baseScore *= 1.35; 
        }
        else if (hardIndicators == 1 && missingPhysics >= 2)
        {
            baseScore *= 1.20;
        }

        if (forgeryScore >= 70)
        {
            baseScore *= 0.45; 
        }
        else if (forgeryScore >= 40)
        {
            baseScore *= 0.70; 
        }
        else if (forgeryScore >= 20)
        {
            baseScore *= 0.85;
        }

        int finalProb = (int)Math.Clamp(Math.Round(baseScore), 0, 100);

        string verdict = finalProb switch
        {
            > 80 => T("Абсолютная ИИ-генерация", "Absolute AI / CGI Generation"),
            > 60 => T("Высокая вероятность ИИ / Синтетическая генерация", "High AI / CGI Probability"),
            > 30 => T("Умеренные признаки ИИ / Digital Art", "Moderate AI / Digital Art signs"),
            _ => T("Естественный снимок / Редактура без ИИ", "Natural Photo or Standard Edit")
        };

        return new AiAnalysisResult(finalProb, verdict, triggers, isMessengerImage);
    }

    private static ForgeryResult AnalyzeForgery(
        MetadataResult meta, 
        LiquifyResult liquify, 
        int cloneCount,
        double noiseInconsistency,
        double elaScore,
        double elaMaxDiff,
        bool isDoubleJpeg,
        double srmScore,
        double bayerScore,
        double highPassNoiseScore,
        double ghost75Score,
        double ghost85Score)
    {
        double score = 0;
        var triggers = new List<string>();

        if (meta.PicsArtDetected)
        {
            score += 35;
            triggers.Add(T("Обнаружены сигнатуры графического редактора в EXIF", "Direct editor signatures found in EXIF"));
        }

        // Проверка наличия независимых физических признаков редактирования/вклейки
        bool hasPhysicalForgery = (liquify.SuspiciousRatioPercent > 12.0) ||
                                  (cloneCount >= 1) ||
                                  (highPassNoiseScore > 35.0) ||
                                  (Math.Max(ghost75Score, ghost85Score) > 40.0) ||
                                  (noiseInconsistency > 38.0) ||
                                  (elaMaxDiff > 14.0 && (elaMaxDiff / (elaScore + 0.1)) > 2.5);

        if (isDoubleJpeg)
        {
            // Двойное квантование JPEG само по себе лишь фиксирует пересохранение файла.
            // Без других физических аномалий оно дает умеренный балл (10%), а при их наличии — усиливает детект (+25%).
            int dqWeight = hasPhysicalForgery ? 25 : 10;
            score += dqWeight;
            triggers.Add(T($"Двойное квантование JPEG (DQ Analysis: файл был открыт и пересохранен, +{dqWeight}%)", 
                           $"Double JPEG Quantization (DQ: File was re-saved in editor, +{dqWeight}%)"));
        }

        if (liquify.SuspiciousRatioPercent > 12.0)
        {
            score += Math.Min(25, (liquify.SuspiciousRatioPercent - 12.0) * 1.2);
            triggers.Add(T($"Локальное сглаживание/ретушь: {liquify.SuspiciousRatioPercent}% аномальных блоков",
                           $"Local smoothing/retouching: {liquify.SuspiciousRatioPercent}% anomalous blocks"));
        }

        if (cloneCount >= 1)
        {
            score += Math.Min(40, cloneCount * 12.0);
            triggers.Add(T($"Обнаружен Штамп / Клонирование: {cloneCount} кластеров (групп смещения)",
                           $"Clone Stamp detected: {cloneCount} distinct spatial clusters"));
        }

        if (highPassNoiseScore > 35.0)
        {
            score += Math.Min(30, (highPassNoiseScore - 30.0) * 1.2);
            triggers.Add(T($"Локальная стерильность / разрыв шума Высоких Частот ({highPassNoiseScore}%): Признак замазывания/вклейки",
                           $"High-Pass noise map inconsistency ({highPassNoiseScore}%): Smooth patch/splicing artifact"));
        }

        double maxGhostScore = Math.Max(ghost75Score, ghost85Score);
        if (maxGhostScore > 40.0)
        {
            score += Math.Min(35, (maxGhostScore - 35.0) * 1.1);
            triggers.Add(T($"Аномалия следов повторного квантования JPEG Ghosts (Индекс: {maxGhostScore}): Обнаружен стык сжатий",
                           $"JPEG Ghost compression artifact ({maxGhostScore}): Multi-stage quantization boundary"));
        }

        if (noiseInconsistency > 38.0) 
        {
            score += Math.Min(50, (noiseInconsistency - 38.0) * 1.8);
            triggers.Add(T($"Грубый локальный разрыв дисперсии шума: {noiseInconsistency}% (Жесткий признак фотомонтажа/вклейки)",
                           $"Noise variance mismatch: {noiseInconsistency}% (Strong Splicing/Insertion sign)"));
        }

        double elaRatio = elaMaxDiff / (elaScore + 0.1);
        if (elaMaxDiff > 14.0 && elaRatio > 2.5)
        {
            score += Math.Min(50, (elaMaxDiff - 12.0) * 1.5);
            triggers.Add(T($"Локальная аномалия ELA (Пик: {elaMaxDiff}, Отношение: {Math.Round(elaRatio, 1)}): Явный признак локальной вклейки/редактирования",
                           $"Local ELA anomaly (Peak: {elaMaxDiff}, Ratio: {Math.Round(elaRatio, 1)}): Splicing artifact detected"));
        }
        else if (elaScore > 12.0)
        {
            score += Math.Min(20, (elaScore - 12.0) * 1.2);
            triggers.Add(T($"Высокий средний уровень ошибки ELA ({elaScore}): Повторное невыровненное сжатие JPEG",
                           $"High ELA variance ({elaScore}): Non-uniform JPEG re-compression"));
        }

        if (score >= 25.0)
        {
            if (srmScore > 12.5)
            {
                score += 15;
                triggers.Add(T($"Аномалия SRM-остатков ({srmScore}) вызвана резкими границами монтажа/вклейки",
                               $"SRM residual anomaly ({srmScore}) caused by splicing borders"));
            }
            if (bayerScore < 5.0 && !meta.IsExifStripped)
            {
                score += 15;
                triggers.Add(T("Разрыв сетки матрицы (Bayer CFA) на границах редактируемых объектов",
                               "Bayer CFA structure disruption along edit boundaries"));
            }
        }

        return new ForgeryResult((int)Math.Clamp(Math.Round(score), 0, 100), triggers);
    }

    private static MetadataResult AnalyzeMetadata(string filePath)
    {
        var reasons = new List<string>();
        var tagsMap = new Dictionary<string, Dictionary<string, string>>();
        bool picsArtFound = false;
        bool hasCameraExif = false;

        try
        {
            foreach (var directory in ImageMetadataReader.ReadMetadata(filePath))
            {
                var dirTags = new Dictionary<string, string>();
                foreach (var tag in directory.Tags)
                {
                    string desc = tag.Description ?? "";
                    dirTags[tag.Name] = desc;

                    string valLower = desc.ToLower();
                    string nameLower = tag.Name.ToLower();

                    if (valLower.Contains("picsart", StringComparison.Ordinal) || 
                        valLower.Contains("picsin", StringComparison.Ordinal) || 
                        valLower.Contains("photoshop", StringComparison.Ordinal) || 
                        valLower.Contains("gimp", StringComparison.Ordinal))
                    {
                        picsArtFound = true;
                        reasons.Add(T($"Сигнатура редактора в теге [{directory.Name} -> {tag.Name}]: '{desc}'",
                                      $"Editor signature in tag [{directory.Name} -> {tag.Name}]: '{desc}'"));
                    }

                    if (nameLower.Contains("model") || nameLower.Contains("make") ||
                        nameLower.Contains("f-number") || nameLower.Contains("exposure") || 
                        nameLower.Contains("iso") || nameLower.Contains("datetimeoriginal") ||
                        nameLower.Contains("focal") || nameLower.Contains("software"))
                    {
                        hasCameraExif = true;
                    }
                }

                if (dirTags.Count > 0)
                    tagsMap[directory.Name] = dirTags;
            }
        }
        catch { }

        bool isStripped = !hasCameraExif;
        if (isStripped && !picsArtFound)
        {
            reasons.Add(T("Метаданные камеры отсутствуют (Типично для мессенджеров или экспорта из веба)",
                          "Camera EXIF missing (Common for messengers or web export)"));
        }

        return new MetadataResult(picsArtFound, reasons, tagsMap, isStripped);
    }

    private static LiquifyResult AnalyzeLiquifyArtifacts(string filePath)
    {
        using var img = Image.Load<Rgb24>(filePath);
        const int blockSize = 16;
        int blocksX = img.Width / blockSize;
        int blocksY = img.Height / blockSize;

        if (blocksX == 0 || blocksY == 0)
            return new LiquifyResult(0, T("Изображение слишком мало для анализа.", "Image is too small for analysis."));

        var variances = new double[blocksX, blocksY];
        var contrasts = new double[blocksX, blocksY];

        Parallel.For(0, blocksX, bx =>
        {
            for (int by = 0; by < blocksY; by++)
            {
                double varSum = 0;
                double minLum = 255;
                double maxLum = 0;
                int count = 0;

                for (int x = bx * blockSize + 1; x < (bx + 1) * blockSize - 1; x++)
                {
                    for (int y = by * blockSize + 1; y < (by + 1) * blockSize - 1; y++)
                    {
                        var p = img[x, y];
                        var pR = img[x + 1, y];
                        var pD = img[x, y + 1];

                        double lum = 0.299 * p.R + 0.587 * p.G + 0.114 * p.B;
                        double lumR = 0.299 * pR.R + 0.587 * pR.G + 0.114 * pR.B;
                        double lumD = 0.299 * pD.R + 0.587 * pD.G + 0.114 * pD.B;

                        if (lum < minLum) minLum = lum;
                        if (lum > maxLum) maxLum = lum;

                        varSum += Math.Abs(lum - lumR) + Math.Abs(lum - lumD);
                        count++;
                    }
                }

                variances[bx, by] = count > 0 ? varSum / count : 0;
                contrasts[bx, by] = maxLum - minLum;
            }
        });

        double totalVariance = 0;
        int totalBlocks = blocksX * blocksY;
        for (int bx = 0; bx < blocksX; bx++)
            for (int by = 0; by < blocksY; by++)
                totalVariance += variances[bx, by];

        double globalAvgVariance = totalVariance / totalBlocks;
        int smoothedBlocks = 0;
        int texturedBlocks = 0;

        for (int bx = 0; bx < blocksX; bx++)
        {
            for (int by = 0; by < blocksY; by++)
            {
                if (contrasts[bx, by] > 12.0) 
                {
                    texturedBlocks++;
                    if (variances[bx, by] < globalAvgVariance * 0.15 && globalAvgVariance > 3.0)
                    {
                        smoothedBlocks++;
                    }
                }
            }
        }

        int evaluatedCount = texturedBlocks > 0 ? texturedBlocks : totalBlocks;
        double suspiciousPercent = (double)smoothedBlocks / evaluatedCount * 100.0;

        string assessment = suspiciousPercent switch
        {
            > 18 => T("Высокая вероятность размытия, использования Фотошопа или ретуши.", "High probability of Photoshop, blur or local retouching."),
            > 10 => T("Умеренная локальная коррекция или сглаживание шума.", "Moderate local correction or noise smoothing."),
            _ => T("Признаков искусственной деформации/ретуши не обнаружено.", "No signs of local retouching detected.")
        };

        return new LiquifyResult(Math.Round(suspiciousPercent, 2), assessment);
    }

    private static Image<Rgb24> GenerateElaMap(string inputPath, out double elaScore, out double elaMaxDiff, int quality = 95, int scale = 20)
    {
        using var original = Image.Load<Rgb24>(inputPath);
        using var tempStream = new MemoryStream();

        original.SaveAsJpeg(tempStream, new JpegEncoder { Quality = quality });
        tempStream.Position = 0;

        using var resaved = Image.Load<Rgb24>(tempStream);
        var elaMap = new Image<Rgb24>(original.Width, original.Height);
        long diffSum = 0;

        const int blockSize = 16;
        int blocksX = Math.Max(1, original.Width / blockSize);
        int blocksY = Math.Max(1, original.Height / blockSize);
        var blockSums = new double[blocksX, blocksY];
        var blockCounts = new int[blocksX, blocksY];

        original.ProcessPixelRows(resaved, elaMap, (origAcc, resavedAcc, elaAcc) =>
        {
            for (int y = 0; y < origAcc.Height; y++)
            {
                var origRow = origAcc.GetRowSpan(y);
                var resavedRow = resavedAcc.GetRowSpan(y);
                var elaRow = elaAcc.GetRowSpan(y);

                int by = Math.Min(y / blockSize, blocksY - 1);

                for (int x = 0; x < origRow.Length; x++)
                {
                    int bx = Math.Min(x / blockSize, blocksX - 1);

                    int diffR = Math.Abs(origRow[x].R - resavedRow[x].R);
                    int diffG = Math.Abs(origRow[x].G - resavedRow[x].G);
                    int diffB = Math.Abs(origRow[x].B - resavedRow[x].B);

                    double pixelDiff = (diffR + diffG + diffB) / 3.0;
                    diffSum += diffR + diffG + diffB;

                    blockSums[bx, by] += pixelDiff;
                    blockCounts[bx, by]++;

                    elaRow[x] = new Rgb24(
                        (byte)Math.Min(255, diffR * scale),
                        (byte)Math.Min(255, diffG * scale),
                        (byte)Math.Min(255, diffB * scale)
                    );
                }
            }
        });

        long totalPixels = (long)original.Width * original.Height;
        elaScore = totalPixels > 0 ? Math.Round((double)diffSum / (totalPixels * 3), 2) : 0;

        double maxBlock = 0;
        for (int bx = 0; bx < blocksX; bx++)
        {
            for (int by = 0; by < blocksY; by++)
            {
                if (blockCounts[bx, by] > 0)
                {
                    double avg = blockSums[bx, by] / blockCounts[bx, by];
                    if (avg > maxBlock) maxBlock = avg;
                }
            }
        }
        elaMaxDiff = Math.Round(maxBlock, 2);

        return elaMap;
    }

    private static double AnalyzeNoiseMismatch(string inputPath, out double globalNoiseLevel)
    {
        globalNoiseLevel = 0;
        using var src = Cv2.ImRead(inputPath, ImreadModes.Grayscale);
        if (src.Empty()) return 0;

        using var gradX = new Mat();
        using var gradY = new Mat();
        Cv2.Sobel(src, gradX, MatType.CV_32F, 1, 0);
        Cv2.Sobel(src, gradY, MatType.CV_32F, 0, 1);
        using var gradMag = new Mat();
        Cv2.Magnitude(gradX, gradY, gradMag);

        using var median = new Mat();
        Cv2.MedianBlur(src, median, 3);
        using var noise = new Mat();
        Cv2.Absdiff(src, median, noise);

        const int blockSize = 32;
        int blocksX = noise.Cols / blockSize;
        int blocksY = noise.Rows / blockSize;

        if (blocksX < 2 || blocksY < 2) return 0;

        var blockStds = new ConcurrentBag<double>();

        Parallel.For(0, blocksX, bx =>
        {
            for (int by = 0; by < blocksY; by++)
            {
                var roi = new Rect(bx * blockSize, by * blockSize, blockSize, blockSize);
                using var blockGrad = new Mat(gradMag, roi);
                Cv2.MeanStdDev(blockGrad, out Scalar meanGrad, out _);
                if (meanGrad.Val0 > 25.0) continue; 

                using var blockNoise = new Mat(noise, roi);
                Cv2.MeanStdDev(blockNoise, out _, out Scalar stddev);
                if (stddev.Val0 > 0.01) blockStds.Add(stddev.Val0);
            }
        });

        var stdsList = blockStds.ToList();
        if (stdsList.Count < 4) return 0;

        stdsList.Sort();
        int trimLow = (int)(stdsList.Count * 0.05);
        int trimHigh = (int)(stdsList.Count * 0.90);
        var trimmedStds = stdsList.Skip(trimLow).Take(Math.Max(1, trimHigh - trimLow)).ToList();

        if (trimmedStds.Count < 2) return 0;

        globalNoiseLevel = Math.Round(trimmedStds.Average(), 2);
        if (globalNoiseLevel < 0.0001) return 0;

        var level = globalNoiseLevel;
        double sumOfSquares = trimmedStds.Sum(d => Math.Pow(d - level, 2));
        double varianceOfStds = Math.Sqrt(sumOfSquares / trimmedStds.Count);

        return Math.Round((varianceOfStds / globalNoiseLevel) * 100.0, 2);
    }

    private static string GenerateHtmlReport(
        string originalPath, MetadataResult meta, LiquifyResult liquify, Image<Rgb24> elaImg,
        ForensicModuleResult noiseRes, ForensicModuleResult copyMoveRes, ForensicModuleResult ghost75Res, ForensicModuleResult ghost85Res,
        ForensicModuleResult fftRes, ForensicModuleResult bayerRes, ForgeryResult forgery, AiAnalysisResult aiResult,
        PrnuResult prnu, SnrResult snr, double srmScore, bool hasC2Pa, bool isDoubleJpeg, bool hasCaAnomaly, double checkerboardScore)
    {
        string origB64 = ImageToBase64(originalPath);
        string elaB64 = ImageToBase64(elaImg);
        string noiseB64 = MatToBase64(noiseRes.RenderMap);
        string copyMoveB64 = MatToBase64(copyMoveRes.RenderMap);
        string ghost75B64 = MatToBase64(ghost75Res.RenderMap);
        string ghost85B64 = MatToBase64(ghost85Res.RenderMap);
        string fftB64 = MatToBase64(fftRes.RenderMap);
        string bayerB64 = MatToBase64(bayerRes.RenderMap);

        string overallVerdict = GetOverallVerdict(forgery.Score, aiResult.AiProbability);

        string scoreColor = forgery.Score >= 45 ? "#ef4444" : (forgery.Score >= 20 ? "#f59e0b" : "#10b981");
        string aiColor = aiResult.AiProbability >= 50 ? "#a855f7" : (aiResult.AiProbability >= 25 ? "#3b82f6" : "#10b981");

        var html = new StringBuilder();
        html.AppendLine($"<!DOCTYPE html><html lang=\"{_currentLang}\"><head><meta charset=\"UTF-8\">");
        html.AppendLine($"<title>{T("Форензик и ИИ Отчет", "Forensics & AI Report")}</title>");
        html.AppendLine("<style>");
        html.AppendLine("  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 25px; }");
        html.AppendLine("  .container { max-width: 1400px; margin: 0 auto; }");
        html.AppendLine("  h1 { color: #38bdf8; border-bottom: 2px solid #0369a1; padding-bottom: 12px; margin-bottom: 20px; }");
        html.AppendLine("  .card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }");
        html.AppendLine("  .score-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }");
        html.AppendLine("  .score-card { display: flex; align-items: center; justify-content: space-between; background: #0f172a; border-radius: 12px; padding: 20px; border: 2px solid #334155; }");
        html.AppendLine("  .score-value { font-size: 38px; font-weight: 800; text-align: right; }");
        html.AppendLine("  .badge { display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 13px; margin-right: 8px; margin-bottom: 6px; }");
        html.AppendLine("  .badge-danger { background: #dc2626; color: #fff; }");
        html.AppendLine("  .badge-warning { background: #d97706; color: #fff; }");
        html.AppendLine("  .badge-success { background: #16a34a; color: #fff; }");
        html.AppendLine("  .badge-purple { background: #9333ea; color: #fff; }");
        html.AppendLine("  .gallery { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; }");
        html.AppendLine("  .gallery-item { background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155; display: flex; flex-direction: column; justify-content: space-between; }");
        html.AppendLine("  .gallery-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }");
        html.AppendLine("  .gallery-item h4 { margin: 0; color: #38bdf8; text-transform: uppercase; font-size: 13px; letter-spacing: 0.5px; }");
        html.AppendLine("  .metric-tag { font-size: 11px; background: #0284c7; color: #fff; padding: 2px 8px; border-radius: 4px; font-weight: bold; }");
        html.AppendLine("  .desc { font-size: 12px; color: #94a3b8; margin-top: 10px; line-height: 1.4; background: #1e293b; padding: 8px 10px; border-radius: 6px; border-left: 3px solid #0284c7; }");
        html.AppendLine("  img { width: 100%; height: auto; border-radius: 6px; display: block; }");
        html.AppendLine("  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }");
        html.AppendLine("  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #334155; }");
        html.AppendLine("  th { background: #0f172a; color: #38bdf8; }");
        html.AppendLine("</style></head><body>");

        html.AppendLine("<div class=\"container\">");
        html.AppendLine($"  <h1> {T("Forensics & AI Detection Report ", "Forensics & AI Detection Report ")}: {Path.GetFileName(originalPath)}</h1>");

        html.AppendLine("  <div class=\"score-grid\">");
        
        html.AppendLine("    <div class=\"score-card\" style=\"border-color: " + scoreColor + ";\">");
        html.AppendLine("      <div>");
        html.AppendLine($"        <h3 style=\"margin:0; color:#f8fafc;\">{T("Шанс Фотошопа / Редакции", "Photoshop / Manipulation")}</h3>");
        html.AppendLine($"        <p style=\"margin: 5px 0 0 0; color:#94a3b8; font-size:12px;\">{T("Вклейки, сглаживание, клонирование", "Collages, smooth blur, cloning")}</p>");
        html.AppendLine("      </div>");
        html.AppendLine($"      <div class=\"score-value\" style=\"color: {scoreColor};\">{forgery.Score}%</div>");
        html.AppendLine("    </div>");

        html.AppendLine("    <div class=\"score-card\" style=\"border-color: " + aiColor + ";\">");
        html.AppendLine("      <div>");
        html.AppendLine($"        <h3 style=\"margin:0; color:#f8fafc;\">{T("Вероятность ИИ / Digital Art", "AI / CGI Probability")}</h3>");
        html.AppendLine($"        <p style=\"margin: 5px 0 0 0; color:#94a3b8; font-size:12px;\">{aiResult.Verdict}</p>");
        html.AppendLine("      </div>");
        html.AppendLine($"      <div class=\"score-value\" style=\"color: {aiColor};\">{aiResult.AiProbability}%</div>");
        html.AppendLine("    </div>");

        html.AppendLine("  </div>");

        html.AppendLine("  <div class=\"card\">");
        html.AppendLine($"    <h2>1. {T("Сводка аномалий и причин детекта", "Anomalies & Triggers Summary")}</h2>");
        
        if (hasC2Pa)
            html.AppendLine("    <span class=\"badge badge-purple\">🔗 C2PA CREDENTIALS</span>");
        if (aiResult.AiProbability > 50)
            html.AppendLine($"    <span class=\"badge badge-purple\">🤖 {T("СИНТЕТИКА / ИИ ДЕТЕКТ", "SYNTHETIC / AI DETECTED")}</span>");
        if (isDoubleJpeg)
            html.AppendLine("    <span class=\"badge badge-danger\">📑 DOUBLE JPEG</span>");
        if (hasCaAnomaly)
            html.AppendLine("    <span class=\"badge badge-warning\">👁️ CA ANOMALY</span>");

        if (aiResult.IsMessengerImage)
            html.AppendLine($"    <span class=\"badge badge-success\">📱 MESSENGER / WEB COMPRESSED</span>");

        if (meta.PicsArtDetected)
            html.AppendLine("    <span class=\"badge badge-danger\">⚠️ EDITOR SIGNATURE</span>");
        else if (meta.IsExifStripped)
            html.AppendLine("    <span class=\"badge badge-warning\">⚡ EXIF STRIPPED</span>");

        html.AppendLine($"    <span class=\"badge badge-success\">PRNU Energy: {prnu.NoiseEnergy}</span>");
        html.AppendLine($"    <span class=\"badge badge-success\">Y/CbCr SNR: {snr.SnrRatio}</span>");
        html.AppendLine($"    <span class=\"badge badge-success\">SRM Score: {srmScore}</span>");
        html.AppendLine($"    <span class=\"badge badge-success\">Checkerboard: {checkerboardScore}</span>");

        html.AppendLine($"    <p style=\"margin-top:15px; color:#f8fafc; font-size:16px;\"><strong>📌 {T("Итоговый вердикт", "Overall Verdict")}:</strong> {overallVerdict}</p>");
        html.AppendLine($"    <p style=\"margin-top:5px; color:#cbd5e1;\"><strong>{T("Оценка ретуши", "Retouch Assessment")}:</strong> {liquify.Assessment}</p>");

        if (meta.DetectionReasons.Count > 0)
        {
            html.AppendLine($"    <h4 style=\"color:#60a5fa; margin-top:15px;\">{T("Обнаруженные метаданные/сигнатуры:", "Detected Metadata/Signatures:")}</h4>");
            html.AppendLine("    <ul>");
            foreach (var r in meta.DetectionReasons) html.AppendLine($"      <li style=\"color:#93c5fd;\">{r}</li>");
            html.AppendLine("    </ul>");
        }

        if (forgery.Triggers.Count > 0)
        {
            html.AppendLine($"    <h4 style=\"color:#f87171; margin-top:15px;\">{T("Причины детекта Фотошопа / Редактирования:", "Photoshop / Editing Detection Triggers:")}</h4>");
            html.AppendLine("    <ul>");
            foreach (var tr in forgery.Triggers) html.AppendLine($"      <li style=\"color:#fca5a5;\">{tr}</li>");
            html.AppendLine("    </ul>");
        }

        if (aiResult.AiTriggers.Count > 0)
        {
            html.AppendLine($"    <h4 style=\"color:#c084fc; margin-top:15px;\">{T("Причины детекта ИИ / Синтетики:", "AI / CGI Detection Triggers:")}</h4>");
            html.AppendLine("    <ul>");
            foreach (var tr in aiResult.AiTriggers) html.AppendLine($"      <li style=\"color:#e9d5ff;\">{tr}</li>");
            html.AppendLine("    </ul>");
        }

        html.AppendLine("  </div>");

        html.AppendLine("  <div class=\"card\">");
        html.AppendLine($"    <h2>2. {T("Галерея визуального и частотного анализа с пояснениями", "Visual & Spectral Analysis Gallery with Explanations")}</h2>");
        html.AppendLine("    <div class=\"gallery\">");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>1. {T("Оригинал снимка", "Original Image")}</h4>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{origB64}\"/>");
        html.AppendLine($"        <div class=\"desc\">{T("Исходное изучаемое изображение для прямого визуального сравнения с математическими картами анализа.", "Original image for direct comparison with mathematical forensic analysis maps.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>2. 2D FFT Spectrum ({T("Спектр Фурье", "Fourier Spectrum")})</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Score: {fftRes.MetricScore}</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{fftB64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Реальные фото имеют плавный звездчатый спад от центра. У ИИ-генераторов (Midjourney, DALL-E) на спектре видны яркие повторяющиеся точки, сетки или звездные кресты — это артефакты Latent VAE / Upscaler.", "Real photos have smooth radial decay from center. AI generators display distinct grid dots, stars or cross patterns caused by Latent VAE artifacts.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>3. Bayer CFA Matrix ({T("Сетка сенсора Байера", "Bayer Grid")})</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Score: {bayerRes.MetricScore}</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{bayerB64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Физические матрицы камер всегда восстанавливают цвет через микро-сетку (Bayer Pattern). У настоящего фото вы увидите мелкую регулярную текстуру 1px. У ИИ или сильной ретуши сетка разрушена или полностью отсутствует.", "Physical camera sensors demosaic color via a 1px Bayer grid. Real photos show fine uniform micro-patterns. AI or heavily retouched photos lack this physical pattern.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>4. Error Level Analysis (ELA)</h4>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{elaB64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Показывает разницу уровней сжатия JPEG. Если область была вклеена из другого файла или отредактирована, она будет светиться значительно ярче/контрастнее оригинального фона.", "Shows compression error variance. Spliced or edited areas will glow much brighter/contrastier than the uniform surrounding original background.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>5. High-Pass Noise Map ({T("Шум сенсора", "Sensor Noise Map")})</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Inconsistency: {noiseRes.MetricScore}%</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{noiseB64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Выделяет высокочастотное 'зерно'. Реальная камера дает равномерный физический шум по всему кадру. ИИ-изображения часто имеют зоны идеальной 'стерильной' гладкости или хаотичные пятна размытия.", "Extracts high-frequency sensor grain. Real cameras produce uniform physical noise. AI renders sterile smooth areas or unnatural noise distribution.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>6. Copy-Move Detection ({T("Детектор Штампа", "Clone Detector")})</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Cluster Score: {copyMoveRes.MetricScore}</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{copyMoveB64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Ищет дублирующиеся группы пикселей. Красные линии со связующими точками показывают использование инструмента 'Штамп' или заклонированные фрагменты объектов.", "Finds duplicate pixel keypoint groups. Red lines connect identical visual structures, indicating Clone Stamp or copy-paste retouching.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>7. JPEG Ghost (Q=75)</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Ghost Index: {ghost75Res.MetricScore}</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{ghost75B64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Поиск следов предыдущего сжатия на уровне качества 75%. Темные однородные области подтверждают оригинальность, яркие силуэты — вклейки из других JPEG.", "Detects prior compression traces at Q75. Dark uniform areas indicate original state, while bright local shadows reveal inserted artifacts.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("      <div class=\"gallery-item\">");
        html.AppendLine("        <div class=\"gallery-header\">");
        html.AppendLine($"          <h4>8. JPEG Ghost (Q=85)</h4>");
        html.AppendLine($"          <span class=\"metric-tag\">Ghost Index: {ghost85Res.MetricScore}</span>");
        html.AppendLine("        </div>");
        html.AppendLine($"        <img src=\"data:image/png;base64,{ghost85B64}\"/>");
        html.AppendLine($"        <div class=\"desc\"><strong>{T("Как читать:", "How to read:")}</strong> {T("Поиск следов повторного пересохранения при высоком качестве (Q85). Позволяет найти скрытые слои сохранения в фоторедакторах.", "Detects secondary re-saves at high quality (Q85). Helps spot hidden editor save cycles.")}</div>");
        html.AppendLine("      </div>");

        html.AppendLine("    </div>");
        html.AppendLine("  </div>");

        html.AppendLine("  <div class=\"card\">");
        html.AppendLine($"    <h2>3. {T("Структура метаданных (EXIF / XMP)", "Metadata Structure (EXIF / XMP)")}</h2>");
        foreach (var dir in meta.AllTags)
        {
            html.AppendLine($"    <h3 style=\"color:#38bdf8;font-size:14px;margin-top:15px;\">{dir.Key}</h3>");
            html.AppendLine($"    <table><tr><th>{T("Тег", "Tag")}</th><th>{T("Значение", "Value")}</th></tr>");
            foreach (var tag in dir.Value)
            {
                html.AppendLine($"      <tr><td>{tag.Key}</td><td>{tag.Value}</td></tr>");
            }
            html.AppendLine("    </table>");
        }
        html.AppendLine("  </div>");

        html.AppendLine("</div></body></html>");

        string outPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"Forensics_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        File.WriteAllText(outPath, html.ToString());
        return outPath;
    }

    private static string ImageToBase64(string path) => Convert.ToBase64String(File.ReadAllBytes(path));

    private static string ImageToBase64(Image<Rgb24> img)
    {
        using var ms = new MemoryStream();
        img.SaveAsPng(ms);
        return Convert.ToBase64String(ms.ToArray());
    }

    private static string MatToBase64(Mat mat)
    {
        if (mat == null || mat.Empty()) return "";
        Cv2.ImEncode(".png", mat, out byte[] buf);
        return Convert.ToBase64String(buf);
    }

    private static void OpenInBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{T("Не удалось автоматически открыть браузер", "Failed to open browser automatically")}: {ex.Message}");
        }
    }
}