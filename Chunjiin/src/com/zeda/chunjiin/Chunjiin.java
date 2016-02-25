/*
* Released under the MIT license
* Copyright (c) 2014 KimYs(a.k.a ZeDA)
* http://blog.naver.com/irineu2
* 
Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

package com.zeda.chunjiin;

import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;

public class Chunjiin
{
	private static final int HANGUL = 0;
	private static final int UPPER_ENGLISH = 1;
	private static final int ENGLISH = 2;
	private static final int NUMBER = 3;
	
	private Button btn[];
	private EditText et;
	private int now_mode = HANGUL;
	
	private class Hangul
	{
		public String chosung = "";
		public String jungsung = "";
		public String jongsung = "";
		public String jongsung2 = "";
		public int step = 0;
		public boolean flag_writing = false;
		public boolean flag_dotused = false;
		public boolean flag_doubled = false;
		public boolean flag_addcursor = false;
		private boolean flag_space = false;
		public void init()
		{
			this.chosung = "";
			this.jungsung = "";
			this.jongsung = "";
			this.jongsung2 = "";
			this.step = 0;
			this.flag_writing = false;
			this.flag_dotused = false;
			this.flag_doubled = false;
			this.flag_addcursor = false;
			this.flag_space = false;
		}
	}
	private Hangul hangul = new Hangul();
	
	private String engnum = "";
	private boolean flag_initengnum = false;
	private boolean flag_engdelete = false;
	private boolean flag_upper = true;
	
	public Chunjiin(EditText editText, Button bt[])
	{
		et = editText;
		et.setOnTouchListener(otl);
		setButton(bt);
	}
	private void setButton(Button inputbtn[])
	{
		btn = inputbtn;
		for(int i=0;i<12;i++)
			btn[i].setOnClickListener(btnlistner);
		btn[12].setOnClickListener(btnchglistner);
		setBtnText(now_mode);
	}

	private final OnTouchListener otl = new OnTouchListener() {
		@Override
		public boolean onTouch(View v, MotionEvent event) {
			v.onTouchEvent(event);
            InputMethodManager imm = (InputMethodManager)v.getContext().getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null)
                imm.hideSoftInputFromWindow(v.getWindowToken(), 0);
   
			hangul.init();
			init_engnum();
			return true;
		}
	};
	
	private final OnClickListener btnlistner = new OnClickListener() {
		@Override
		public void onClick(View v) {
			int input = -1;
			switch(v.getId())
			{
				case R.id.chunjiin_button0:	input = 0;	break;
				case R.id.chunjiin_button1:	input = 1;	break;
				case R.id.chunjiin_button2:	input = 2;	break;
				case R.id.chunjiin_button3:	input = 3;	break;
				case R.id.chunjiin_button4:	input = 4;	break;
				case R.id.chunjiin_button5:	input = 5;	break;
				case R.id.chunjiin_button6:	input = 6;	break;
				case R.id.chunjiin_button7:	input = 7;	break;
				case R.id.chunjiin_button8:	input = 8;	break;
				case R.id.chunjiin_button9:	input = 9;	break;
				case R.id.chunjiin_buttonex1:	input = 10;	break;
				case R.id.chunjiin_buttonex2:	input = 11;	break;
			}
			if(input == -1)
				return;
			if(now_mode == HANGUL)
				hangulMake(input);
			else if((now_mode == ENGLISH || now_mode == UPPER_ENGLISH))
				engMake(input);
			else // if(now_mode == NUMBER)
				numMake(input);
			
			write(now_mode);
		}
	};
	private final OnClickListener btnchglistner = new OnClickListener() {
		@Override
		public void onClick(View v) {
			now_mode = (now_mode == NUMBER) ? HANGUL : now_mode+1 ;
			setBtnText(now_mode);
			hangul.init();
			init_engnum();
		}
	};
 
	private void init_engnum()
	{
		engnum = "";
		flag_initengnum = false;
		flag_engdelete = false;
	}
	private void write(int mode)
	{
		int position = et.getSelectionStart();
		String origin = "";
		String str = "";
		origin = et.getText().toString();
		
		if(mode == HANGUL)
		{
			boolean dotflag = false;
			boolean doubleflag = false;
			boolean spaceflag = false;
			
			String real_jongsung = checkDouble(hangul.jongsung, hangul.jongsung2);
			if(real_jongsung.length() == 0)
			{
				real_jongsung = hangul.jongsung;
				if(hangul.jongsung2.length() != 0)
					doubleflag = true;
			}
	
			char unicode = (char)getUnicode(real_jongsung);

			if(!hangul.flag_writing)
				str += origin.substring(0, position);
			else if(hangul.flag_dotused)
			{
				if(hangul.chosung.length() == 0)
					str += origin.substring(0, position-1);
				else
					str += origin.substring(0, position-2);
			}
			else if(hangul.flag_doubled)
				str += origin.substring(0, position-2);
			else
				str += origin.substring(0, position-1);

			
			if(unicode != 0)
				str += String.valueOf(unicode);
			if(hangul.flag_space)
			{
				str += " ";
				hangul.flag_space = false;
				spaceflag = true;
			}
			
			if(doubleflag)
			{
				str += hangul.jongsung2;
			}
			if(hangul.jungsung.equals("��"))
			{
				str += "��";
				dotflag = true;
			}
			else if(hangul.jungsung.equals("��"))
			{
				str += "��";
				dotflag = true;
			}
			
			str += origin.substring(position, origin.length());
			et.setText(str);
			
			if(dotflag)
				position++;
			if(doubleflag)
			{
				if(!hangul.flag_doubled)
					position++;
				hangul.flag_doubled = true;
			}
			else
			{
				if(hangul.flag_doubled)
					position--;
				hangul.flag_doubled = false;
			}
			if(spaceflag)
				position++;
			if(unicode == 0 && dotflag == false)
				position--;
			if(hangul.flag_addcursor)
			{
				hangul.flag_addcursor = false;
				position++;
			}
			
			if(hangul.flag_dotused)
			{
				if(hangul.chosung.length() == 0 && dotflag == false)
					et.setSelection(position);
				else
					et.setSelection(position-1);
			}
			else if(!hangul.flag_writing && dotflag == false)
				et.setSelection(position + 1);
			else
				et.setSelection(position);
			
			hangul.flag_dotused = false;
			hangul.flag_writing = (unicode == 0 && dotflag == false) ? false : true;
		}
		else //if(mode == ENGLISH || mode == UPPER_ENGLISH || mode == NUMBER)
		{
			if(flag_engdelete)
				str += origin.substring(0, position-1);
			else
				str += origin.substring(0, position);
			
			if(flag_upper || mode == NUMBER)
				str += engnum;
			else
				str += engnum.toLowerCase();
			
			if(flag_engdelete)
			{
				str += origin.substring(position, origin.length());
				et.setText(str);
				et.setSelection(position);
				flag_engdelete = false;
			}
			else
			{
				str += origin.substring(position, origin.length());
				et.setText(str);
				if(engnum.length() == 0)
					et.setSelection(position);
				else
					et.setSelection(position+1);
			}
			
			if(flag_initengnum)
				init_engnum();
		}
	}
	private void delete()
	{
		int position = et.getSelectionStart();
		if(position == 0)
			return;
		
		String origin = "";
		String str = "";
	
		origin = et.getText().toString();
		str += origin.substring(0, position-1);
		str += origin.substring(position, origin.length());
		et.setText(str);
		et.setSelection(position-1);
	}
	private void engMake(int input)
	{
		if(input == 10) // ����
		{
			if(engnum.length()==0)
				engnum = " ";
			else
				engnum = "";
			flag_initengnum = true;
		}
		else if(input == 11) // �����
		{
			delete();
			init_engnum();
		}
		else
		{
			String str = "";
			switch(input)
			{
				case 0 : str = "@?!"; break;
				case 1 : str = ".QZ"; break;
				case 2 : str = "ABC"; break;
				case 3 : str = "DEF"; break;
				case 4 : str = "GHI"; break;
				case 5 : str = "JKL"; break;
				case 6 : str = "MNO"; break;
				case 7 : str = "PRS"; break;
				case 8 : str = "TUV"; break;
				case 9 : str = "WXY"; break;
				default : return;
			}
			
			char ch[] = str.toCharArray();

			if(engnum.length() == 0)
				engnum = String.valueOf(ch[0]);
			else if(engnum.equals(String.valueOf(ch[0])))
			{
				engnum = String.valueOf(ch[1]);
				flag_engdelete = true;
			}
			else if(engnum.equals(String.valueOf(ch[1])))
			{
				engnum = String.valueOf(ch[2]);
				flag_engdelete = true;
			}
			else if(engnum.equals(String.valueOf(ch[2])))
			{
				engnum = String.valueOf(ch[0]);
				flag_engdelete = true;
			}
			else
				engnum = String.valueOf(ch[0]);
		}
	}
	private void numMake(int input)
	{
		if(input == 10) // ����
			engnum = " ";
		else if(input == 11) // �����
			delete();
		else
			engnum = Integer.toString(input);

		flag_initengnum = true;
	}
	private void hangulMake(int input)
	{
		String beforedata = "";
		String nowdata = "";
		String overdata = "";
		if(input == 10) //����
		{
			if(hangul.flag_writing)
				hangul.init();
			else
				hangul.flag_space = true;
		}
		else if(input == 11) //�����
		{
			if(hangul.step == 0)
			{
				if(hangul.chosung.length() == 0)
				{
					delete();
					hangul.flag_writing = false;
				}
				else
					hangul.chosung = "";
			}
			else if(hangul.step == 1)
			{
				if(hangul.jungsung.equals("��") || hangul.jungsung.equals("��"))
				{
					delete();
					if(hangul.chosung.length() == 0)
						hangul.flag_writing = false;
				}
				hangul.jungsung = "";
				hangul.step = 0;
			}
			else if(hangul.step == 2)
			{
				hangul.jongsung = "";
				hangul.step = 1;
			}
			else if(hangul.step == 3)
			{
				hangul.jongsung2 = "";
				hangul.step = 2;
			}
		}
		else if(input == 1 || input == 2 || input == 3) //����
		{
			//��ħ���� ������°� �߰��ؾ���
			boolean batchim = false;
			if(hangul.step == 2)
			{
				delete();
				String s = hangul.jongsung;
				hangul.jongsung = "";
				hangul.flag_writing = false;
				write(now_mode);
				hangul.init();
				hangul.chosung = s;
				hangul.step = 0;
				batchim = true;
			}
			else if(hangul.step == 3)
			{
				String s = hangul.jongsung2;
				if(hangul.flag_doubled)
					delete();
				else
				{
					delete();
					hangul.jongsung2 = "";
					hangul.flag_writing = false;
					write(now_mode);
				}
				hangul.init();
				hangul.chosung = s;
				hangul.step = 0;
				batchim = true;
			}
			beforedata = hangul.jungsung;
			hangul.step = 1;
			if(input == 1) // �� �� �� �� �� �Ƥ� �� �� �� �� �� ��
			{
				if(beforedata.length() == 0)		nowdata = "��";
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else
				{
					hangul.init();
					hangul.step = 1;
					nowdata = "��";
				}
			}
			else if(input == 2) // ��,��,��,��,��,��,��
			{
				if(beforedata.length() == 0)
				{
					nowdata = "��";
					if(batchim)
						hangul.flag_addcursor = true;
				}
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else if(beforedata.equals("��"))	nowdata = "��";
				else
				{
					hangul.init();
					hangul.step = 1;
					nowdata = "��";
				}
			}
			else if(input == 3) // ��, ��, ��
			{
				if(beforedata.length() == 0)		nowdata = "��";
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else if(beforedata.equals("��"))
				{
					nowdata = "��";
					hangul.flag_dotused = true;
				}
				else
				{
					hangul.init();
					hangul.step = 1;
					nowdata = "��";
				}
			}
			hangul.jungsung = nowdata;
		}
		else //����
		{
			if(hangul.step == 1)
			{
				if(hangul.jungsung.equals("��") || hangul.jungsung.equals("��"))
					hangul.init();
				else
					hangul.step = 2;
			}
			if(hangul.step == 0)		beforedata = hangul.chosung;
			else if(hangul.step == 2)	beforedata = hangul.jongsung;
			else if(hangul.step == 3)	beforedata = hangul.jongsung2;

			if(input == 4) // ��, ��, ��, ��
			{
				if(beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if(beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			else if(input == 5) // �� ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else
					overdata = "��";
			}
			else if(input == 6) // ��, ��, ��, ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			else if(input == 7) // ��, ��, ��, ��, ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			else if(input == 8) // ��, ��, ��, ��, ��, ��, ��, ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			else if(input == 9) // ��, ��, ��, ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			else if(input == 0) // ��, ��, ��
			{
				if (beforedata.length() == 0)
				{
					if(hangul.step == 2)
					{
						if(hangul.chosung.length() == 0)
							overdata = "��";
						else
							nowdata = "��";
					}
					else
						nowdata = "��";
				}
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if (beforedata.equals("��"))
					nowdata = "��";
				else if(beforedata.equals("��") && hangul.step == 2)
				{
					hangul.step = 3;
					nowdata = "��";
				}
				else
					overdata = "��";
			}
			
			if(nowdata.length() > 0)
			{
				if(hangul.step == 0)
					hangul.chosung = nowdata;
				else if(hangul.step == 2)
					hangul.jongsung = nowdata;
				else //if(hangul.step == 3)
					hangul.jongsung2 = nowdata;
			}
			if(overdata.length() > 0)
			{
				hangul.flag_writing = false;
				hangul.init();
				hangul.chosung = overdata;
			}
		}
	}
		
	private void setBtnText(int mode)
	{
		switch(mode)
		{
			case HANGUL:
				btn[0].setText("����");
				btn[1].setText("��");
				btn[2].setText("��");
				btn[3].setText("��");
				btn[4].setText("����");
				btn[5].setText("����");
				btn[6].setText("����");
				btn[7].setText("����");
				btn[8].setText("����");
				btn[9].setText("����");
				break;
			case UPPER_ENGLISH:
				btn[0].setText("@?!");
				btn[1].setText(".QZ");
				btn[2].setText("ABC");
				btn[3].setText("DEF");
				btn[4].setText("GHI");
				btn[5].setText("JKL");
				btn[6].setText("MNO");
				btn[7].setText("PRS");
				btn[8].setText("TUV");
				btn[9].setText("WXY");
				flag_upper = true;
				break;
			case ENGLISH:
				btn[0].setText("@?!");
				btn[1].setText(".qz");
				btn[2].setText("abc");
				btn[3].setText("def");
				btn[4].setText("ghi");
				btn[5].setText("jkl");
				btn[6].setText("mno");
				btn[7].setText("prs");
				btn[8].setText("tuv");
				btn[9].setText("wxy");
				flag_upper = false;
				break;
			case NUMBER:
				for(int i=0;i<10;i++)
					btn[i].setText(Integer.toString(i));
				break;
		}
	}
	
	private int getUnicode(String real_jong)
	{
		int cho, jung, jong;
		//�ʼ�
		if(hangul.chosung.length() == 0)
		{
			if(hangul.jungsung.length() == 0 || hangul.jungsung.equals("��") || hangul.jungsung.equals("��"))
				return 0;
		}
		
		if ( hangul.chosung.equals("��"))	cho = 0;
		else if ( hangul.chosung.equals("��"))	cho = 1;
		else if ( hangul.chosung.equals("��"))	cho = 2;
		else if ( hangul.chosung.equals("��"))	cho = 3;
		else if ( hangul.chosung.equals("��"))	cho = 4;
		else if ( hangul.chosung.equals("��"))	cho = 5;
		else if ( hangul.chosung.equals("��"))	cho = 6;
		else if ( hangul.chosung.equals("��"))	cho = 7;
		else if ( hangul.chosung.equals("��"))	cho = 8;
		else if ( hangul.chosung.equals("��"))	cho = 9;
		else if ( hangul.chosung.equals("��"))	cho = 10;
		else if ( hangul.chosung.equals("��"))	cho = 11;
		else if ( hangul.chosung.equals("��"))	cho = 12;
		else if ( hangul.chosung.equals("��"))	cho = 13;
		else if ( hangul.chosung.equals("��"))	cho = 14;
		else if ( hangul.chosung.equals("��"))	cho = 15;
		else if ( hangul.chosung.equals("��"))	cho = 16;
		else if ( hangul.chosung.equals("��"))	cho = 17;
		else /*if ( hangul.chosung.equals("��"))*/	cho = 18;
		
		if (hangul.jungsung.length() == 0 && hangul.jongsung.length() == 0)
			return 0x1100 + cho;
		if (hangul.jungsung.equals("��") || hangul.jungsung.equals("��"))
			return 0x1100 + cho;
		
		// �߼�
		if ( hangul.jungsung.equals("��"))		jung = 0;
		else if ( hangul.jungsung.equals("��"))	jung = 1;
		else if ( hangul.jungsung.equals("��"))	jung = 2;
		else if ( hangul.jungsung.equals("��"))	jung = 3;
		else if ( hangul.jungsung.equals("��"))	jung = 4;
		else if ( hangul.jungsung.equals("��"))	jung = 5;
		else if ( hangul.jungsung.equals("��"))	jung = 6;
		else if ( hangul.jungsung.equals("��"))	jung = 7;
		else if ( hangul.jungsung.equals("��"))	jung = 8;
		else if ( hangul.jungsung.equals("��"))	jung = 9;
		else if ( hangul.jungsung.equals("��"))	jung = 10;
		else if ( hangul.jungsung.equals("��"))	jung = 11;
		else if ( hangul.jungsung.equals("��"))	jung = 12;
		else if ( hangul.jungsung.equals("��"))	jung = 13;
		else if ( hangul.jungsung.equals("��"))	jung = 14;
		else if ( hangul.jungsung.equals("��"))	jung = 15;
		else if ( hangul.jungsung.equals("��"))	jung = 16;
		else if ( hangul.jungsung.equals("��"))	jung = 17;
		else if ( hangul.jungsung.equals("��"))	jung = 18;
		else if ( hangul.jungsung.equals("��"))	jung = 19;
		else /*if ( hangul.jungsung.equals("��"))*/	jung = 20;
		
		if ( hangul.chosung.length() == 0 && hangul.jongsung.length() == 0)
			return 0x1161 + jung;
		
		// ����
		if ( real_jong.length() == 0)		jong = 0;
		else if ( real_jong.equals("��"))	jong = 1;
		else if ( real_jong.equals("��"))	jong = 2;
		else if ( real_jong.equals("��"))	jong = 3;
		else if ( real_jong.equals("��"))	jong = 4;
		else if ( real_jong.equals("��"))	jong = 5;
		else if ( real_jong.equals("��"))	jong = 6;
		else if ( real_jong.equals("��"))	jong = 7;
		else if ( real_jong.equals("��"))	jong = 8;
		else if ( real_jong.equals("��"))	jong = 9;
		else if ( real_jong.equals("��"))	jong = 10;
		else if ( real_jong.equals("��"))	jong = 11;
		else if ( real_jong.equals("��"))	jong = 12;
		else if ( real_jong.equals("��"))	jong = 13;
		else if ( real_jong.equals("��"))	jong = 14;
		else if ( real_jong.equals("��"))	jong = 15;
		else if ( real_jong.equals("��"))	jong = 16;
		else if ( real_jong.equals("��"))	jong = 17;
		else if ( real_jong.equals("��"))	jong = 18;
		else if ( real_jong.equals("��"))	jong = 19;
		else if ( real_jong.equals("��"))	jong = 20;
		else if ( real_jong.equals("��"))	jong = 21;
		else if ( real_jong.equals("��"))	jong = 22;
		else if ( real_jong.equals("��"))	jong = 23;
		else if ( real_jong.equals("��"))	jong = 24;
		else if ( real_jong.equals("��"))	jong = 25;
		else if ( real_jong.equals("��"))	jong = 26;
		else /*if ( real_jong.equals("��"))*/	jong = 27;
		
		if ( hangul.chosung.length() == 0 && hangul.jungsung.length() == 0)
			return 0x11a8 + jong;
		
		return 44032 + cho*588 + jung*28 + jong;
	}
	
	private String checkDouble(String jong, String jong2)
	{
		String s = "";
		if (jong.equals("��"))
		{
			if (jong2.equals("��"))		s = "��";
		}
		else if (jong.equals("��"))
		{
			if (jong2.equals("��"))		s = "��";
			else if (jong2.equals("��"))	s = "��";
		}
		else if (jong.equals("��"))
		{
			if (jong2.equals("��"))		s = "��";
			else if (jong2.equals("��"))	s = "��";
			else if (jong2.equals("��"))	s = "��";
			else if (jong2.equals("��"))	s = "��";
			else if (jong2.equals("��"))	s = "��";
			else if (jong2.equals("��"))	s = "��";
			else if (jong2.equals("��"))	s = "��";
		}
		else if (jong.equals("��"))
		{
			if (jong2.equals("��"))		s = "��";
		}
		return s;
	}
}
