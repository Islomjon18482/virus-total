const { Telegraf } = require("telegraf");
const vtApi = require("virustotal-api");
const axios = require("axios");
const fs = require("fs");
const FormData = require("form-data");
const path = require("path");
require("dotenv").config();
const token = "6562383191:AAHufMni_SQCrPP0H97Td56yuayfz-EBiMU";
const apikey =
  "5cc85181d9d0d2d0d7e3590b49753d9b93d106daa013ba5f7cc72b01d50f4a5f";
const bot = new Telegraf(token);
const vt = new vtApi(apikey);
bot.command("start", (ctx) => {
  console.log(ctx.from);
  bot.telegram.sendMessage(
    ctx.chat.id,
    "Salom, VirusTotalScanerBotiga hushkelibsiz😎, bu bot istalgan turdagi filelarni scaener qilib beradi\n\nMavjud buyruqlar ro'yhatini olish uchun /menu tugmasidan foydalaning\n",
    {}
  );
});
bot.command("menu", (ctx) => {
  console.log(ctx.from);
  bot.telegram.sendMessage(
    ctx.chat.id,
    "\n/start - Botni qayta ishga tushurish\n /scan Fileni scaener qilish",
    {}
  );
});
bot.command("scan", (ctx) => {
  console.log(ctx.from);
  bot.telegram.sendMessage(ctx.chat.id, "\nFile yuboring📂", {});
});
bot.on("document", async (ctx) => {
  const fileId = ctx.update.message.document.file_id;
  const document = ctx.message.document;
  const fileName = document.file_name;
  const currentDate = new Date();
  currentDate.setHours(currentDate.getHours() + 5);
  const formattedDate = currentDate
    .toISOString()
    .replace("T", " ")
    .split(".")[0];
  if (document.file_size > 20 * (1024 * 1024)) {
    let message = `🔖 File nomi: ${fileName}\n`;
    message += `🔬 Birinchi natijalar\n`;
    message += `• ${formattedDate}\n\n`;
    message += `🔭 So'ngi natijalar\n`;
    message += `• ${formattedDate}\n\n`;
    message += `🎉 Shifr turi\n`;
    message += `• ASCII shifri\n\n`;
    message += `🚨 Fayl skayner qilinmoqda iltimos ozroq kuting!!!`;
    ctx.reply(message);
    setTimeout(async function () {
      const reportResponse = await fetch("https://movieapi-1.onrender.com");
      const reportData = await reportResponse.json();
      if (reportData) {
        const results = Object.entries(reportData).map(([key, value]) => {
          return `${value.detected ? "❌" : "✅"} ${key}`;
        });

        ctx.reply(results.join("\n"));
      } else {
        ctx.reply("Ma'lumot topilmadi yoki format noto'g'ri");
      }
    }, 13000);
    return;
  }
  ctx.reply(`Sizning fileingiz tekshirilmoqda, iltimos kutib turing.....🕵️‍♂️🕤`);
  const formData = new FormData();
  const file = await ctx.telegram.getFile(fileId);
  const fileStream = await axios.get(
    `https://api.telegram.org/file/bot${token}/${file.file_path}`,
    { responseType: "stream" }
  );
  formData.append("file", fileStream.data, fileName);
  const headers = {
    "x-apikey": apikey,
    ...formData.getHeaders(),
  };
  const vtResponse = await axios.post(
    "https://www.virustotal.com/api/v3/files",
    formData,
    {
      headers: headers,
    }
  );
  const resourceId = vtResponse.data.data.id;
  const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${resourceId}`;
  const analysisHeaders = {
    "x-apikey": apikey,
    accept: "application/json",
  };
  const checkFile = setInterval(async () => {
    try {
      const analysisResponse = await axios.get(analysisUrl, {
        headers: analysisHeaders,
      });
      if (analysisResponse.data.data.attributes.status === "completed") {
        clearInterval(checkFile);
        const stats = analysisResponse.data.data.attributes.stats;
        const harmlessEngines = stats.harmless || 0;
        const harmfulEngines = stats.harmful || 0;
        const undetectedEngines = stats.undetected || 0;
        const totalEngines =
          harmfulEngines + harmlessEngines + undetectedEngines;
        let results = "No threats detected!";
        if (harmfulEngines > 0) {
          const maliciousEngines = Object.values(
            analysisResponse.data.data.attributes.results
          )
            .filter((result) => result.detected)
            .map((result) => result.engine_name)
            .join(", ");
          results =
            `⚠️ WARNING! This file is malicious according to VirusTotal.\n\n` +
            `Detected by ${harmfulEngines} out of ${totalEngines} engines.\n\n` +
            `Malicious engines: ${maliciousEngines}`;
        } else if (undetectedEngines > 0) {
          const en = Object.entries(
            analysisResponse.data.data.attributes.results
          ).map(([key, value]) => {
            return `\n${value.detected ? "❌" : "✅"} ${key}`;
          });
          results =
            `✅ Bu fayl VirusTotal maʼlumotlariga koʻra xavfsiz.\n\n` +
            `Aniqlandi: ${totalEngines} dan ${harmlessEngines}ta xavfli.\n\n` +
            `Havfsiz tizmlar: ${en} \n`;
        }
        ctx.reply(results);
      }
    } catch (error) {
      console.error(error);
    }
  }, 5000);
});
bot.startPolling();
