#include "pch.h"
#include "../libspng/spng.h"

#include "Susie.hpp"

#include <type_traits>
#include <limits>
#include <string>
#include <memory>

using namespace std::string_literals;

template <class F>
constexpr inline F bitwiseOr(F a, F b) noexcept
{
	return static_cast<F>(static_cast<typename std::underlying_type<F>::type>(a) | static_cast<typename std::underlying_type<F>::type>(b));
}

template <class F>
constexpr inline F bitwiseAnd(F a, F b) noexcept
{
	return static_cast<F>(static_cast<typename std::underlying_type<F>::type>(a)& static_cast<typename std::underlying_type<F>::type>(b));
}

constexpr inline SUSIE_RESULT SpngToSpiResult(int error) noexcept
{
	switch (error)
	{
	case SPNG_OK:
		return SUSIE_RESULT::ALL_RIGHT;
	case SPNG_IO_ERROR:
		return SUSIE_RESULT::FILE_READ_ERROR;
	case SPNG_IO_EOF:
		return SUSIE_RESULT::SPI_END_OF_FILE;
	case SPNG_EMEM:
		return SUSIE_RESULT::SPI_NO_MEMORY;
	case SPNG_ESIGNATURE:
	case SPNG_ECHUNK_POS:
	case SPNG_ECHUNK_SIZE:
	case SPNG_ECHUNK_CRC:
	case SPNG_ECHUNK_TYPE:
	case SPNG_ECHUNK_UNKNOWN_CRITICAL:
		return SUSIE_RESULT::OUT_OF_ORDER;

		/*
				return SUSIE_RESULT::SPI_E_ABORT;
				return SUSIE_RESULT::NOT_SUPPORT;
				return SUSIE_RESULT::MEMORY_ERROR;
				return SUSIE_RESULT::SPI_WINDOW_ERROR;
				return SUSIE_RESULT::OTHER_ERROR;

			SPNG_EINVAL,
			SPNG_EOVERFLOW,
			SPNG_EWIDTH,
			SPNG_EHEIGHT,
			SPNG_EUSER_WIDTH,
			SPNG_EUSER_HEIGHT,
			SPNG_EBIT_DEPTH,
			SPNG_ECOLOR_TYPE,
			SPNG_ECOMPRESSION_METHOD,
			SPNG_EFILTER_METHOD,
			SPNG_EINTERLACE_METHOD,
			SPNG_EIHDR_SIZE,
			SPNG_ENOIHDR,
			SPNG_EDUP_PLTE,
			SPNG_EDUP_CHRM,
			SPNG_EDUP_GAMA,
			SPNG_EDUP_ICCP,
			SPNG_EDUP_SBIT,
			SPNG_EDUP_SRGB,
			SPNG_EDUP_BKGD,
			SPNG_EDUP_HIST,
			SPNG_EDUP_TRNS,
			SPNG_EDUP_PHYS,
			SPNG_EDUP_TIME,
			SPNG_EDUP_OFFS,
			SPNG_EDUP_EXIF,
			SPNG_ECHRM,
			SPNG_EPLTE_IDX,
			SPNG_ETRNS_COLOR_TYPE,
			SPNG_ETRNS_NO_PLTE,
			SPNG_EGAMA,
			SPNG_EICCP_NAME,
			SPNG_EICCP_COMPRESSION_METHOD,
			SPNG_ESBIT,
			SPNG_ESRGB,
			SPNG_ETEXT,
			SPNG_ETEXT_KEYWORD,
			SPNG_EZTXT,
			SPNG_EZTXT_COMPRESSION_METHOD,
			SPNG_EITXT,
			SPNG_EITXT_COMPRESSION_FLAG,
			SPNG_EITXT_COMPRESSION_METHOD,
			SPNG_EITXT_LANG_TAG,
			SPNG_EITXT_TRANSLATED_KEY,
			SPNG_EBKGD_NO_PLTE,
			SPNG_EBKGD_PLTE_IDX,
			SPNG_EHIST_NO_PLTE,
			SPNG_EPHYS,
			SPNG_ESPLT_NAME,
			SPNG_ESPLT_DUP_NAME,
			SPNG_ESPLT_DEPTH,
			SPNG_ETIME,
			SPNG_EOFFS,
			SPNG_EEXIF,
			SPNG_EIDAT_TOO_SHORT,
			SPNG_EIDAT_STREAM,
			SPNG_EZLIB,
			SPNG_EFILTER,
			SPNG_EBUFSIZ,
			SPNG_EIO,
			SPNG_EOF,
			SPNG_EBUF_SET,
			SPNG_EBADSTATE,
			SPNG_EFMT,
			SPNG_EFLAGS,
			SPNG_ECHUNKAVAIL,
			SPNG_ENCODE_ONLY,
		*/
	}
	return SUSIE_RESULT::OTHER_ERROR;
}

int32_t WINAPI GetPluginInfo(int32_t infono, LPSTR  buf, int32_t buflen)
{
	switch (infono)
	{
	case 0:
		if (::strcpy_s(buf, buflen, "00IN") != 0)
		{
			return 0;
		}
		break;
	case 1:
		if (::sprintf_s(buf, buflen, "iflibspng build with %d.%d.%d",
			SPNG_VERSION_MAJOR, SPNG_VERSION_MINOR, SPNG_VERSION_PATCH) == -1)
		{
			return 0;
		}
		break;
	case 2:
		strcpy_s(buf, buflen, "*.png");
		break;
	case 3:
		strcpy_s(buf, buflen, "PNG File(*.png)");
		break;
	default:
		return 0;
	}
	return static_cast<int>(std::strlen(buf));
}
int32_t WINAPI GetPluginInfoW(int32_t infono, LPWSTR buf, int32_t buflen)
{
	return 0;
}

BOOL WINAPI IsSupported(LPCSTR /* filename */, void* dw)
{
	BYTE buf[2048];
	const BYTE* header = buf;
	if ((DWORD_PTR)dw & (~(DWORD_PTR)0xffff))
	{
		header = (BYTE*)dw;
	}
	else
	{
		DWORD size = 0;
		if (ReadFile(reinterpret_cast<HANDLE>(dw), buf, sizeof(buf), &size, nullptr) == FALSE)
		{
			return FALSE;
		}
	}

	constexpr BYTE sig[4] = { 0x89, 'P', 'N','G' };

	return memcmp(header, sig, sizeof(sig)) == 0;
}
BOOL WINAPI IsSupportedW(LPCWSTR filename, void* dw)
{
	return FALSE;
}

typedef std::unique_ptr<spng_ctx, decltype(&::spng_ctx_free)> SpngCtx;

template <class T>
SUSIE_RESULT GetPictureImpl(LPCSTR buf, size_t len, bool isMemoryInput, T continueFunc) noexcept
{
	SpngCtx ctx{ ::spng_ctx_new(0), &spng_ctx_free };

	if (ctx == nullptr)
		return SUSIE_RESULT::SPI_NO_MEMORY;

	std::unique_ptr<void, decltype(&::CloseHandle)> hFile{ nullptr, &::CloseHandle };

	int ret = SPNG_OK;
	if (isMemoryInput)
	{
		ret = ::spng_set_png_buffer(ctx.get(), buf, len);
	}
	else
	{
		hFile.reset(CreateFileA(buf, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (hFile.get() == INVALID_HANDLE_VALUE)
			return SUSIE_RESULT::FILE_READ_ERROR;

		ret = ::spng_set_png_stream(ctx.get(),
			+[](spng_ctx*, void* user, void* dest, size_t length) -> int
			{
				DWORD dwRead = 0;
				if (!::ReadFile(user, dest, length, &dwRead, nullptr))
					return SPNG_IO_ERROR;
				if (dwRead < length)
					return SPNG_IO_EOF;
				return 0;
			}, hFile.get());
	}

	if (SPNG_OK != ret)
		return SpngToSpiResult(ret);
	spng_ihdr ihdr{};
	ret = spng_get_ihdr(ctx.get(), &ihdr);
	if (SPNG_OK != ret)
		return SpngToSpiResult(ret);

	return continueFunc(ctx, ihdr);

}

SUSIE_RESULT WINAPI GetPictureInfo(LPCSTR buf, size_t len, SUSIE_FLAG flag, SUSIE_PICTUREINFO* lpInfo)
{
	if (buf == nullptr || lpInfo == nullptr)
		return SUSIE_RESULT::NO_FUNCTION;

	return GetPictureImpl(buf, len, bitwiseAnd(flag, SUSIE_FLAG::SPI_INPUT_MASK) == SUSIE_FLAG::SPI_INPUT_MEMORY,
		[lpInfo](SpngCtx& ctx, auto &ihdr) {
			*lpInfo = {};
			lpInfo->width = ihdr.width;
			lpInfo->height = ihdr.height;
			lpInfo->x_density = lpInfo->y_density = 96;
			lpInfo->colorDepth = ihdr.bit_depth;
			spng_text text{};
			uint32_t textLen;
			spng_get_text(ctx.get(), &text, &textLen);
			if (text.text)
			{
				lpInfo->hInfo = ::LocalAlloc(LPTR, text.length + 1);
				if (lpInfo->hInfo)
				{
					memcpy(lpInfo->hInfo, text.text, text.length);
					::LocalUnlock(lpInfo->hInfo);
				}
			}
			return SUSIE_RESULT::ALL_RIGHT;
		});
}
SUSIE_RESULT WINAPI GetPictureInfoW(LPCWSTR buf, size_t len, SUSIE_FLAG flag, SUSIE_PICTUREINFO* lpInfo)
{
	return SUSIE_RESULT::NO_FUNCTION;
}

SUSIE_RESULT WINAPI GetPicture(LPCSTR buf, size_t len, SUSIE_FLAG flag, HLOCAL* pHBInfo, HLOCAL* pHBm, SUSIE_PROGRESS progressCallback, intptr_t lData)
{
	if (buf == nullptr || pHBInfo == nullptr || pHBm == nullptr)
		return SUSIE_RESULT::NO_FUNCTION;
	return GetPictureImpl(buf, len, bitwiseAnd(flag, SUSIE_FLAG::SPI_INPUT_MASK) == SUSIE_FLAG::SPI_INPUT_MEMORY,
		[pHBInfo, pHBm](SpngCtx& ctx, auto &ihdr) {
			int ret = SPNG_OK;
			size_t bufferSize = 0;
			ret = ::spng_decoded_image_size(ctx.get(), SPNG_FMT_RGBA8, &bufferSize);

			spng_plte pallet{};
			bool hasPallet = spng_get_plte(ctx.get(), &pallet) == SPNG_OK;

			typedef std::unique_ptr<void, decltype(&::LocalFree)> LocalPtr;
			std::unique_ptr<BITMAPINFOHEADER, decltype(&::LocalFree)> pBInfo{
				static_cast<BITMAPINFOHEADER*>(::LocalAlloc(LPTR, sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * 256)),& ::LocalFree };
		
			if (pBInfo == nullptr)
				return SUSIE_RESULT::SPI_NO_MEMORY;

			*pBInfo = {
				sizeof(BITMAPINFOHEADER),
				static_cast<LONG>(ihdr.width),
				-static_cast<LONG>(ihdr.height),
				1,
				static_cast<WORD>(ihdr.bit_depth * 4u), // biBitCount
				0, // biCompression
				1,
				1,
				static_cast<LONG>(pallet.n_entries),
				//biClrImportant
			};

			if (SPNG_OK != ret)
				return SpngToSpiResult(ret);

			RGBQUAD* colorTable = reinterpret_cast<RGBQUAD*>(pBInfo.get() + 1);

			for (INT i = 0; i < 256; i++)
			{
				colorTable[i].rgbBlue = colorTable[i].rgbGreen = colorTable[i].rgbRed = static_cast<BYTE>(i);
			}

			LocalPtr pBm{ ::LocalAlloc(LPTR, bufferSize), &::LocalFree };
			if(pBm == nullptr)
				return SUSIE_RESULT::SPI_NO_MEMORY;

			ret = spng_decode_image(ctx.get(), reinterpret_cast<BYTE*>(pBm.get()), bufferSize, SPNG_FMT_RGBA8, 0);
			if (SPNG_OK != ret)
				return SpngToSpiResult(ret);

			auto pPixel = reinterpret_cast<DWORD*>(pBm.get());
			for (size_t i = 0; i < (bufferSize / sizeof(*pPixel)); i ++ )
			{
				//  RGBA -> BGRA
				pPixel[i] =
					((pPixel[i] & 0x000000FF) << 16) |
					((pPixel[i] & 0x0000FF00)) |
					((pPixel[i] & 0x00FF0000) >> 16) |
					((pPixel[i] & 0xFF000000) );
			}


			*pHBInfo = pBInfo.release();
			::LocalUnlock(*pHBInfo);

			*pHBm = pBm.release();
			::LocalUnlock(*pHBm);

			return SUSIE_RESULT::ALL_RIGHT;
		});
}
SUSIE_RESULT WINAPI GetPictureW(LPCWSTR buf, size_t len, SUSIE_FLAG flag, HLOCAL* pHBInfo, HLOCAL* pHBm, SUSIE_PROGRESS progressCallback, intptr_t lData)
{

	return SUSIE_RESULT::NO_FUNCTION;
}

SUSIE_RESULT WINAPI GetPreview(LPCSTR  buf, size_t len, SUSIE_FLAG flag, HLOCAL* pHBInfo, HLOCAL* pHBm, SUSIE_PROGRESS progressCallback, intptr_t lData)
{
	return SUSIE_RESULT::NO_FUNCTION;
}

SUSIE_RESULT WINAPI GetPreviewW(LPCWSTR buf, size_t len, SUSIE_FLAG flag, HLOCAL* pHBInfo, HLOCAL* pHBm, SUSIE_PROGRESS progressCallback, intptr_t lData)
{
	return SUSIE_RESULT::NO_FUNCTION;
}

SUSIE_RESULT WINAPI ConfigurationDlg(HWND parent, int fnc)
{
	return SUSIE_RESULT::NO_FUNCTION;
}

