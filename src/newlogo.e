-> EModule with imagedatas for MUI - generated by brush2e.

OPT MODULE
OPT EXPORT
OPT PREPROCESS

MODULE 'datatypes/pictureclass'
MODULE 'muimaster', 'libraries/mui'
MODULE 'utility/tagitem'

CONST IMG_GPLOGO_WIDTH       =  38
CONST IMG_GPLOGO_HEIGHT      =  26
CONST IMG_GPLOGO_DEPTH       =   6
CONST IMG_GPLOGO_COMPRESSION =   1
CONST IMG_GPLOGO_MASKING     =   0

PROC imgGplogoHeader() IS [38,26,0,0,6,0,1,0,0,1,1,38,26]:bitmapheader

PROC imgGplogoBody() IS
 [$05,$FA,$00,$00,$01,$3C,$00,$00,$04,$FC,$00,$00,$02,$FE,$00,
  $01,$40,$00,$05,$03,$00,$00,$01,$80,$00,$00,$04,$FE,$00,$01,
  $40,$00,$03,$03,$00,$00,$01,$FF,$00,$00,$C0,$FE,$00,$01,$0C,
  $00,$FB,$00,$00,$20,$FC,$00,$FD,$00,$01,$10,$00,$00,$20,$FC,
  $00,$FB,$00,$00,$C0,$FE,$00,$01,$04,$00,$FB,$00,$FB,$00,$FD,
  $00,$01,$08,$00,$FB,$00,$FB,$00,$00,$C0,$FC,$00,$FB,$00,$00,
  $40,$FE,$00,$01,$04,$00,$FD,$00,$01,$04,$00,$00,$40,$FC,$00,
  $FD,$00,$01,$04,$00,$FD,$00,$01,$04,$00,$FB,$00,$00,$80,$FE,
  $00,$01,$04,$00,$FB,$00,$00,$80,$FE,$00,$01,$04,$00,$FB,$00,
  $FB,$00,$FB,$00,$FB,$00,$00,$80,$FC,$00,$FB,$00,$FB,$00,$02,
  $80,$00,$09,$FE,$00,$02,$00,$00,$0A,$FE,$00,$02,$00,$00,$04,
  $FE,$00,$02,$80,$00,$08,$FE,$00,$02,$00,$00,$09,$FE,$00,$02,
  $80,$00,$05,$FE,$00,$02,$00,$00,$80,$FE,$00,$02,$00,$00,$FF,
  $FE,$00,$02,$00,$00,$80,$FE,$00,$FE,$00,$00,$80,$FF,$00,$03,
  $00,$00,$80,$80,$FF,$00,$FB,$00,$03,$00,$01,$40,$80,$FF,$00,
  $03,$00,$01,$FF,$80,$FF,$00,$02,$00,$01,$48,$FE,$00,$03,$00,
  $00,$78,$80,$FF,$00,$03,$00,$01,$78,$80,$FF,$00,$FB,$00,$02,
  $00,$02,$02,$FE,$00,$02,$01,$03,$86,$FE,$00,$02,$00,$02,$85,
  $FE,$00,$02,$01,$00,$84,$FE,$00,$02,$00,$02,$05,$FE,$00,$02,
  $00,$00,$03,$FE,$00,$03,$00,$C0,$00,$01,$FF,$00,$03,$07,$47,
  $00,$01,$FF,$00,$01,$04,$01,$FD,$00,$03,$04,$C5,$00,$01,$FF,
  $00,$03,$04,$C4,$00,$01,$FF,$00,$01,$00,$04,$FD,$00,$05,$00,
  $40,$00,$01,$C0,$00,$05,$0F,$8E,$00,$00,$40,$00,$01,$08,$08,
  $FD,$00,$05,$08,$48,$00,$01,$40,$00,$05,$00,$42,$00,$01,$C0,
  $00,$05,$00,$02,$00,$00,$80,$00,$FD,$00,$01,$20,$00,$00,$0F,
  $FE,$FF,$01,$C0,$00,$FB,$00,$FB,$00,$FD,$00,$01,$20,$00,$FD,
  $00,$01,$20,$00,$03,$08,$3F,$1F,$FE,$FF,$00,$05,$0F,$C0,$E0,
  $01,$C0,$00,$05,$08,$3F,$BF,$FE,$40,$00,$03,$00,$00,$A0,$01,
  $FF,$00,$05,$08,$00,$A0,$00,$40,$00,$05,$08,$00,$00,$01,$40,
  $00,$00,$04,$FC,$00,$03,$03,$C0,$70,$01,$FF,$00,$02,$00,$00,
  $10,$FE,$00,$03,$04,$40,$10,$01,$FF,$00,$03,$04,$40,$40,$01,
  $FF,$00,$03,$00,$00,$40,$01,$FF,$00,$03,$00,$00,$20,$80,$FF,
  $00,$03,$03,$80,$38,$F0,$FF,$00,$03,$01,$00,$28,$48,$FF,$00,
  $03,$03,$80,$08,$C0,$FF,$00,$03,$02,$00,$20,$B8,$FF,$00,$FE,
  $00,$00,$38,$FF,$00,$03,$00,$00,$10,$08,$FF,$00,$03,$00,$00,
  $1F,$78,$FF,$00,$03,$00,$00,$10,$08,$FF,$00,$03,$00,$00,$07,
  $80,$FF,$00,$03,$00,$00,$14,$88,$FF,$00,$FE,$00,$00,$08,$FF,
  $00,$03,$00,$00,$08,$08,$FF,$00,$03,$00,$00,$0F,$F8,$FF,$00,
  $02,$00,$00,$08,$FE,$00,$FB,$00,$02,$00,$00,$08,$FE,$00,$FE,
  $00,$00,$08,$FF,$00,$FE,$00,$00,$08,$FF,$00,$FE,$00,$00,$F8,
  $FF,$00,$FB,$00,$FE,$00,$00,$80,$FF,$00,$FB,$00,$FE,$00,$00,
  $08,$FF,$00,$00,$80,$FC,$00,$FB,$00,$FB,$00,$00,$80,$FC,$00,
  $FB,$00,$00,$80,$FC,$00,$FB,$00,$FB,$00,$FB,$00,$00,$80,$FC,
  $00,$FB,$00,$FB,$00,$FD,$00,$01,$04,$00,$FB,$00,$00,$80,$FE,
  $00,$01,$04,$00,$FB,$00,$00,$80,$FE,$00,$01,$04,$00,$FB,$00,
  $00,$C0,$FC,$00,$FB,$00,$00,$40,$FE,$00,$01,$04,$00,$FD,$00,
  $01,$04,$00,$00,$40,$FC,$00,$FD,$00,$01,$04,$00,$00,$C0,$FE,
  $00,$01,$04,$00,$FB,$00,$FB,$00,$FD,$00,$01,$08,$00,$FB,$00,
  $FB,$00,$00,$C0,$FE,$00,$01,$0C,$00,$FB,$00,$00,$20,$FC,$00,
  $FD,$00,$01,$10,$00,$00,$20,$FC,$00,$FB,$00,$00,$F0,$FE,$00,
  $01,$5C,$00,$FB,$00,$FD,$00,$01,$60,$00,$00,$08,$FE,$00,$01,
  $20,$00,$FD,$00,$01,$40,$00,$FD,$00,$01,$20,$00]:CHAR

PROC imgGplogoColors() IS
 [$99999999,$99999999,$CCCCCCCC,
  $66666666,$66666666,$99999999,
  $FFFFFFFF,$FFFFFFFF,$FFFFFFFF,
  $8F8F8F8F,$8F8F8F8F,$B4B4B4B4,
  $F5F5F5F5,$F5F5F5F5,$FAFAFAFA,
  $AEAEAEAE,$AEAEAEAE,$D6D6D6D6,
  $CFCFCFCF,$CFCFCFCF,$E7E7E7E7,
  $ACACACAC,$ACACACAC,$C8C8C8C8,
  $82828282,$82828282,$B5B5B5B5,
  $4F4F4F4F,$38383838,$82828282,
  $9E9E9E9E,$9E9E9E9E,$CECECECE,
  $EBEBEBEB,$EBEBEBEB,$F2F2F2F2,
  $5C5C5C5C,$52525252,$8F8F8F8F,
  $D6D6D6D6,$D6D6D6D6,$E3E3E3E3,
  $C5C5C5C5,$C5C5C5C5,$E2E2E2E2,
  $3E3E3E3E,$16161616,$71717171,
  $61616161,$5C5C5C5C,$94949494,
  $4A4A4A4A,$2E2E2E2E,$7D7D7D7D,
  $7A7A7A7A,$7A7A7A7A,$ADADADAD,
  $54545454,$42424242,$87878787,
  $6B6B6B6B,$6B6B6B6B,$9E9E9E9E,
  $8F8F8F8F,$8F8F8F8F,$C2C2C2C2,
  $79797979,$79797979,$A6A6A6A6,
  $B3B3B3B3,$B3B3B3B3,$D9D9D9D9,
  $A5A5A5A5,$A5A5A5A5,$D2D2D2D2,
  $FDFDFDFD,$FDFDFDFD,$FEFEFEFE,
  $BCBCBCBC,$BCBCBCBC,$DEDEDEDE,
  $9B9B9B9B,$9B9B9B9B,$CDCDCDCD,
  $F5F5F5F5,$F5F5F5F5,$F8F8F8F8,
  $39393939,$0C0C0C0C,$6C6C6C6C,
  $DBDBDBDB,$DBDBDBDB,$EDEDEDED,
  $D5D5D5D5,$D5D5D5D5,$EAEAEAEA,
  $A3A3A3A3,$A3A3A3A3,$C1C1C1C1,
  $E8E8E8E8,$E8E8E8E8,$F4F4F4F4,
  $70707070,$70707070,$9F9F9F9F,
  $EDEDEDED,$EDEDEDED,$F6F6F6F6,
  $F6F6F6F6,$F6F6F6F6,$FBFBFBFB,
  $E1E1E1E1,$E1E1E1E1,$EDEDEDED,
  $99999999,$99999999,$BBBBBBBB,
  $41414141,$1D1D1D1D,$74747474,
  $97979797,$97979797,$CACACACA,
  $92929292,$92929292,$C5C5C5C5,
  $FBFBFBFB,$FBFBFBFB,$FDFDFDFD,
  $65656565,$64646464,$98989898,
  $6F6F6F6F,$6F6F6F6F,$A2A2A2A2,
  $8C8C8C8C,$8C8C8C8C,$BFBFBFBF,
  $36363636,$06060606,$69696969,
  $B8B8B8B8,$B8B8B8B8,$D0D0D0D0,
  $C2C2C2C2,$C2C2C2C2,$D6D6D6D6,
  $E4E4E4E4,$E4E4E4E4,$F1F1F1F1,
  $C1C1C1C1,$C1C1C1C1,$E0E0E0E0,
  $83838383,$83838383,$ACACACAC,
  $BABABABA,$BABABABA,$DCDCDCDC,
  $5D5D5D5D,$53535353,$90909090,
  $BFBFBFBF,$BFBFBFBF,$DFDFDFDF,
  $F0F0F0F0,$F0F0F0F0,$F8F8F8F8,
  $AAAAAAAA,$AAAAAAAA,$D5D5D5D5,
  $F9F9F9F9,$F9F9F9F9,$FCFCFCFC,
  $B7B7B7B7,$B7B7B7B7,$DBDBDBDB,
  $CCCCCCCC,$CCCCCCCC,$DDDDDDDD,
  $F8F8F8F8,$F8F8F8F8,$FBFBFBFB,
  $FEFEFEFE,$FEFEFEFE,$FEFEFEFE,
  $FEFEFEFE,$FEFEFEFE,$FFFFFFFF,
  $FFFFFFFF,$FFFFFFFF,$FFFFFFFF]

PROC imgGplogoObject()
DEF object

  object:=BodychunkObject,
    MUIA_Bodychunk_Body,        imgGplogoBody(),
    MUIA_Bodychunk_Masking,     IMG_GPLOGO_MASKING,
    MUIA_Bodychunk_Compression, IMG_GPLOGO_COMPRESSION,
    MUIA_Bodychunk_Depth,       IMG_GPLOGO_DEPTH,
    MUIA_Bitmap_Height,         IMG_GPLOGO_HEIGHT,
    MUIA_Bitmap_Width,          IMG_GPLOGO_WIDTH,
    MUIA_FixHeight,             IMG_GPLOGO_HEIGHT,
    MUIA_FixWidth,              IMG_GPLOGO_WIDTH,
    MUIA_Bitmap_SourceColors,   imgGplogoColors(),
    MUIA_Frame,                 MUIV_Frame_String,
    MUIA_HorizDisappear,        MUI_TRUE,
    MUIA_VertDisappear,         MUI_TRUE,
  End

ENDPROC object
