const scrapBtn = document.querySelector('#scrap_btn');
const loadingBtn = document.querySelector('#loading_btn');

scrapBtn.addEventListener("click", function () {
    if (document.querySelector("#input1").value !== "") {
        loadingBtn.style.display = "block";
        scrapBtn.style.display = "none";
        scrapFileBtn.disabled = true;
    }
});

const scrapFileBtn = document.querySelector('#scrap_file_btn');
const loadingFileBtn = document.querySelector('#loading_file_btn');

scrapFileBtn.addEventListener("click", function () {
    if (document.querySelector("#input2").value !== "") {
        loadingFileBtn.style.display = "block";
        scrapFileBtn.style.display = "none";
        scrapBtn.disabled = true;
    }
});
