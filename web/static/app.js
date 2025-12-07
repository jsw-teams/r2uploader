document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('upload-form');
  const result = document.getElementById('result');

  if (!form) return;

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    result.textContent = '正在上传...';

    const formData = new FormData(form);

    try {
      const resp = await fetch('/upload', {
        method: 'POST',
        body: formData
      });

      const data = await resp.json().catch(() => null);
      if (!resp.ok || !data || !data.ok) {
        result.textContent = (data && data.error) || '上传失败';
        return;
      }

      const link = document.createElement('a');
      link.href = data.url;
      link.textContent = data.url;
      link.target = '_blank';

      result.innerHTML = '';
      result.appendChild(document.createTextNode('上传成功：'));
      result.appendChild(document.createElement('br'));
      result.appendChild(link);
    } catch (err) {
      console.error(err);
      result.textContent = '上传出错，请稍后重试';
    }
  });
});
