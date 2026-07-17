package com.omega.console.local

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.omega.console.local.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val prefs = getSharedPreferences(getString(R.string.prefs_name), Context.MODE_PRIVATE)
        val savedUrl = prefs.getString(
            getString(R.string.prefs_key_url),
            getString(R.string.default_device_url)
        ) ?: getString(R.string.default_device_url)

        binding.urlInput.setText(savedUrl)
        setupWebView()
        setupActions(prefs)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (binding.webView.canGoBack()) {
                    binding.webView.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        loadUrl(savedUrl)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(binding.webView, true)

        binding.webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            loadWithOverviewMode = true
            useWideViewPort = true
            builtInZoomControls = true
            displayZoomControls = false
            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            cacheMode = WebSettings.LOAD_DEFAULT
            allowFileAccess = false
            allowContentAccess = false
        }

        binding.webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView?,
                request: WebResourceRequest?
            ): Boolean = false

            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                binding.progress.visibility = View.VISIBLE
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                binding.progress.visibility = View.GONE
                if (!url.isNullOrBlank()) {
                    binding.urlInput.setText(url)
                }
            }
        }

        binding.webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                binding.progress.visibility =
                    if (newProgress in 1..99) View.VISIBLE else View.GONE
            }
        }
    }

    private fun setupActions(prefs: android.content.SharedPreferences) {
        binding.loadBtn.setOnClickListener { commitAndLoad(prefs) }
        binding.reloadBtn.setOnClickListener { binding.webView.reload() }
        binding.homeBtn.setOnClickListener {
            val home = prefs.getString(
                getString(R.string.prefs_key_url),
                getString(R.string.default_device_url)
            ) ?: getString(R.string.default_device_url)
            binding.urlInput.setText(home)
            loadUrl(home)
        }

        binding.urlInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                commitAndLoad(prefs)
                true
            } else {
                false
            }
        }
    }

    private fun commitAndLoad(prefs: android.content.SharedPreferences) {
        val raw = binding.urlInput.text?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            Toast.makeText(this, R.string.error_empty_url, Toast.LENGTH_SHORT).show()
            return
        }
        val url = normalizeUrl(raw)
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            Toast.makeText(this, R.string.error_bad_url, Toast.LENGTH_SHORT).show()
            return
        }
        prefs.edit().putString(getString(R.string.prefs_key_url), url).apply()
        binding.urlInput.setText(url)
        loadUrl(url)
    }

    private fun normalizeUrl(raw: String): String {
        val trimmed = raw.trim()
        return when {
            trimmed.startsWith("http://") || trimmed.startsWith("https://") -> trimmed
            trimmed.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/.*)?$""")) ->
                "http://$trimmed"
            else -> trimmed
        }
    }

    private fun loadUrl(url: String) {
        binding.webView.loadUrl(url)
    }
}
